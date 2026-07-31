"""Make the updater trust the same CAs the host does, cosign included.

The updater's outbound TLS is not all Python: ``cosign verify`` is a Go binary we shell out to,
and it reaches the registry and the Sigstore transparency log itself. So the agent's approach of
building an ``ssl.SSLContext`` cannot work here, because nothing would hand that context to a
subprocess.

``SSL_CERT_FILE`` is the one lever both halves respect: Python's ``ssl`` picks it up through
OpenSSL's default verify paths, and Go's ``crypto/x509`` reads the same variable on Linux. So we
merge the image's bundle with whatever CAs are mounted, write the result once at startup, and
export it into our own environment, which every child process inherits.

Without this, a network that inspects TLS leaves the updater failing closed forever: cosign
cannot verify a signature it cannot fetch, so the agent silently stops updating while looking
perfectly healthy. That is a worse failure than the agent's, because nothing reports it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("ares.updater.tls")

# Mirrors agent.tlsconf: the host CA directory the install command mounts, and the manual drop-in.
HOST_CA_DIR = Path("/host-ca")
EXTRA_CA_DIR = Path("/certs")
# Alpine's system bundle, the base we merge on top of so public roots survive.
IMAGE_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
# Written at startup. /tmp so this works whether or not the updater runs as root.
MERGED_BUNDLE = Path("/tmp/ares-ca-bundle.pem")  # noqa: S108 - deliberate, see above

_PEM_SUFFIXES = frozenset({".crt", ".pem", ".cer"})


def _pems_in(directory: Path) -> list[Path]:
    """Every readable PEM directly inside ``directory``, sorted; empty when it is not mounted.

    Skips anything that is not a readable regular file in silence: a mounted ``/etc/ssl/certs``
    brings ~150 symlinks that dangle inside the container, and they are not worth a line each.
    """
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []
    return [path for path in entries if path.suffix in _PEM_SUFFIXES and path.is_file()]


def install_ca_bundle() -> Path | None:
    """Merge the mounted CAs with the image bundle and point ``SSL_CERT_FILE`` at the result.

    Returns the bundle path, or ``None`` when there is nothing mounted and the image's own store
    is already the whole truth. Never raises: a broken CA mount must not stop the updater from
    running, it should only stop it from trusting more than it did before.
    """
    if os.environ.get("SSL_CERT_FILE"):
        # An operator set it explicitly. Theirs wins; we do not second-guess it.
        return None
    mounted = _pems_in(HOST_CA_DIR) + _pems_in(EXTRA_CA_DIR)
    if not mounted:
        return None

    chunks: list[str] = []
    for source in [IMAGE_BUNDLE, *mounted]:
        try:
            chunks.append(source.read_text(encoding="utf-8", errors="ignore"))
        except OSError as exc:
            logger.warning("Ignoring CA file %s: %s", source, exc)
    if not chunks:
        return None

    try:
        MERGED_BUNDLE.write_text("\n".join(chunks), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not write the merged CA bundle to %s: %s", MERGED_BUNDLE, exc)
        return None

    os.environ["SSL_CERT_FILE"] = str(MERGED_BUNDLE)
    logger.info(
        "TLS trust: image store plus %d mounted CA file(s) -> %s", len(mounted), MERGED_BUNDLE
    )
    return MERGED_BUNDLE
