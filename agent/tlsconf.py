"""Where the agent's TLS trust comes from.

One SSL context, shared by the control plane and the data-plane tunnel, so the two can never
disagree about what is trusted. It is the **union** of every CA we can find, never a replacement:

* the image's own store (which also honours ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``),
* certifi's public roots, so those are present even where a store is thin,
* every PEM under :data:`HOST_CA_DIR` and :data:`EXTRA_CA_DIR`,
* whatever ``ARES_CA_BUNDLE`` names.

The reason this module exists: httpx does **not** use the OS trust store. Given ``verify=True``
it verifies against ``certifi.where()``, a PEM inside site-packages, unless ``SSL_CERT_FILE`` or
``SSL_CERT_DIR`` is set. So on a network that inspects TLS, an operator can install their root CA
in the container the ordinary way (``update-ca-certificates``), watch ``urllib`` succeed, and
still have every agent request fail with ``CERTIFICATE_VERIFY_FAILED``. That is not a
configuration mistake, it is two trust stores in one container, and it cost a customer a week.

Discovery is deliberately zero-configuration. A network that inspects TLS has already had to make
its root trusted on the host, or nothing on that machine could browse; the install command mounts
that host directory read-only at :data:`HOST_CA_DIR`, and the agent picks it up with nothing to
set. A host with no interception mounts an ordinary public bundle, which is a harmless no-op.
"""

from __future__ import annotations

import logging
import ssl
from collections import Counter
from functools import lru_cache
from pathlib import Path

import certifi
from pydantic import BaseModel, ConfigDict

logger = logging.getLogger("ares.agent.tls")

# The host's own CA directory, mounted read-only by the install command. Read-only, and only ever
# the public certificate directory: /etc/ssl/private is never mounted.
HOST_CA_DIR = Path("/host-ca")
# The manual drop-in, for a root that is not in the host store: an internal CA on an air-gapped
# build, or a Kubernetes ConfigMap, where there is no host directory to mount.
EXTRA_CA_DIR = Path("/certs")

_PEM_SUFFIXES = frozenset({".crt", ".pem", ".cer"})


class AgentTrust(BaseModel):
    """The trust the agent ended up with, and where each part of it came from."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    context: ssl.SSLContext
    loaded: tuple[Path, ...] = ()
    rejected: tuple[Path, ...] = ()

    @property
    def verifies(self) -> bool:
        """Whether certificates are checked at all.

        Derived from the context rather than stored alongside it, so the two cannot drift apart.
        False only under ARES_INSECURE, which main.py already refuses against a production URL.
        """
        return self.context.verify_mode != ssl.CERT_NONE

    def summary(self) -> str:
        """One line for the startup log, so ``docker logs`` answers "did it see my CA?" before
        anything has failed rather than after."""
        if not self.verifies:
            return "verification DISABLED (ARES_INSECURE)"
        parts = ["image store", "certifi"]
        # Grouped by directory, because which mount worked is the useful half of the answer:
        # "/host-ca (1 file)" says the host store came through, "/certs (1 file)" the drop-in did.
        for directory, count in sorted(Counter(path.parent for path in self.loaded).items()):
            parts.append(f"{directory} ({count} file{'' if count == 1 else 's'})")
        line = ", ".join(parts)
        if self.rejected:
            line += f"; unreadable: {', '.join(str(path) for path in self.rejected)}"
        return line


def _pems_in(directory: Path) -> list[Path]:
    """Every readable PEM directly inside ``directory``, sorted; empty when it is not there.

    Anything that is not a readable regular file is skipped **in silence**. That is not laziness:
    ``/etc/ssl/certs`` on a Debian host is one real bundle plus ~150 symlinks into
    ``/usr/share/ca-certificates``, and mounting the directory alone leaves every one of those
    dangling inside the container. Warning about each on every start would bury the one line that
    matters.
    """
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []  # not mounted, which is the normal case
    return [path for path in entries if path.suffix in _PEM_SUFFIXES and path.is_file()]


def _candidate_files(ca_bundle: str) -> list[Path]:
    """The extra CA files to load on top of the image store and certifi."""
    paths = _pems_in(HOST_CA_DIR) + _pems_in(EXTRA_CA_DIR)
    if not ca_bundle:
        return paths
    # ARES_CA_BUNDLE takes a file or a directory, because operators reasonably expect both. A
    # named file is passed through unfiltered, suffix and all: they told us to trust it, and a
    # path that turns out not to exist should say so rather than vanish.
    configured = Path(ca_bundle)
    return paths + (_pems_in(configured) if configured.is_dir() else [configured])


@lru_cache(maxsize=None)
def build_trust(*, insecure: bool, ca_bundle: str) -> AgentTrust:
    """The agent's trust, built once and shared.

    Cached because ``control_plane`` opens a fresh ``AsyncClient`` per call: without it, every
    heartbeat and every task poll would re-parse the whole bundle. An ``SSLContext`` is meant to
    be shared across connections, so handing the same one out is the intended use.

    Both arguments are required on purpose. ``lru_cache`` keys on the arguments as *written*, so
    with defaults ``build_trust()`` and ``build_trust(insecure=False, ca_bundle="")`` would be two
    cache entries holding two different contexts, and the "one context for the whole agent"
    promise above would quietly hold only because every caller happened to spell it the same way.
    """
    if insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return AgentTrust(context=context)

    # The image's own store first. This is also what picks up SSL_CERT_FILE / SSL_CERT_DIR, so an
    # operator who already set either (the documented fix for older agents) keeps working.
    context = ssl.create_default_context()
    # certifi on top, never instead: a store that has been narrowed to one corporate root must not
    # cost us the public roots.
    context.load_verify_locations(cafile=certifi.where())

    loaded: list[Path] = []
    rejected: list[Path] = []
    for path in _candidate_files(ca_bundle):
        try:
            context.load_verify_locations(cafile=str(path))
        except OSError as exc:  # ssl.SSLError is an OSError; so is an unreadable file
            # Loud, because this one *is* an operator mistake: a file they meant us to trust and
            # we could not. One bad file never costs us the rest.
            logger.warning("Ignoring CA file %s: %s", path, exc)
            rejected.append(path)
        else:
            loaded.append(path)
    return AgentTrust(context=context, loaded=tuple(loaded), rejected=tuple(rejected))


def verification_hint(exc: BaseException, *, insecure: bool, ca_bundle: str) -> str:
    """A remedy to append to a connection error, when that error is a certificate rejection.

    Returns ``""`` for every other failure, and is prefixed with its own space when it is not
    empty, so a caller can append it unconditionally. The raw OpenSSL string ("self-signed
    certificate in certificate chain") tells an operator what happened and nothing about what to
    do, which is exactly the gap that turns a five-minute mount into a week of email.
    """
    seen: set[int] = set()
    cause: BaseException | None = exc
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, ssl.SSLCertVerificationError):
            trust = build_trust(insecure=insecure, ca_bundle=ca_bundle)
            return (
                " Nothing in the agent's trust store signed that certificate, which usually means "
                "the network is inspecting TLS. Re-run the install command from the dashboard "
                "(Settings -> Agents): it mounts this host's CA store into the container. Or "
                "mount your root CA yourself with -v /path/to/ca-dir:/certs:ro. "
                f"Trust loaded: {trust.summary()}."
            )
        cause = cause.__cause__ or cause.__context__
    return ""
