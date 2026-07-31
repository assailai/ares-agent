"""The agent's CA trust: what it discovers, what it refuses to be fooled by, and the two call
sites that must keep using it.

The bug these guard against is subtle enough to have cost a customer a week. httpx given
``verify=True`` verifies against certifi's bundle *inside site-packages* and ignores the OS trust
store, so an operator can install their corporate root in the container, watch ``urllib`` succeed,
and still have every agent request fail. The regression tests at the bottom are the ones that
matter most: they assert the agent hands httpx and websockets an explicit context, not a bare
``True``.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

import pytest
import trustme

from agent import control_plane, tlsconf
from agent.config import Settings


@pytest.fixture(autouse=True)
def _isolate_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point discovery at tmp_path and drop the cache, so tests never see the real /host-ca
    (or each other's contexts, which lru_cache would happily hand back)."""
    host_ca = tmp_path / "host-ca"
    extra = tmp_path / "certs"
    monkeypatch.setattr(tlsconf, "HOST_CA_DIR", host_ca)
    monkeypatch.setattr(tlsconf, "EXTRA_CA_DIR", extra)
    tlsconf.build_trust.cache_clear()
    yield host_ca, extra
    tlsconf.build_trust.cache_clear()


def _build(*, insecure: bool = False, ca_bundle: str = "") -> tlsconf.AgentTrust:
    """build_trust with test defaults. The real one takes both arguments required, so that two
    spellings cannot cache two different contexts (see its docstring); the defaults live here
    instead, where a second context costs nothing."""
    return tlsconf.build_trust(insecure=insecure, ca_bundle=ca_bundle)


def _hint(exc: BaseException) -> str:
    """verification_hint with the same test defaults."""
    return tlsconf.verification_hint(exc, insecure=False, ca_bundle="")


def _write_ca(directory: Path, name: str) -> tuple[Path, str]:
    """A real CA PEM on disk, plus the organization name to look for in a loaded context."""
    directory.mkdir(parents=True, exist_ok=True)
    organization = f"{name}.test"
    authority = trustme.CA(organization_name=organization)
    path = directory / f"{name}.crt"
    authority.cert_pem.write_to_path(str(path))
    return path, organization


def _organizations(context: ssl.SSLContext) -> set[str]:
    return {
        value
        for cert in context.get_ca_certs()
        for rdn in cert.get("subject", ())
        for key, value in rdn
        if key == "organizationName"
    }


def test_given_nothing_mounted_then_public_roots_are_still_trusted() -> None:
    """The normal case for every customer who is not behind an inspecting proxy."""
    trust = _build()

    assert trust.verifies
    assert trust.loaded == ()
    assert trust.rejected == ()
    # certifi alone is hundreds of roots; an empty store would mean we broke ordinary TLS.
    assert len(trust.context.get_ca_certs()) > 50
    assert trust.summary() == "image store, certifi"


def test_given_a_ca_in_host_ca_then_it_is_trusted_alongside_the_public_roots(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """The whole point: the install command mounts the host store, and the agent picks it up
    with nothing configured."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "corp-root")

    trust = _build()

    assert organization in _organizations(trust.context)
    assert len(trust.context.get_ca_certs()) > 50  # union, never replacement
    assert [path.name for path in trust.loaded] == ["corp-root.crt"]
    assert "(1 file)" in trust.summary()


def test_given_a_ca_in_certs_then_it_is_trusted(_isolate_trust: tuple[Path, Path]) -> None:
    """The manual drop-in, which is how Kubernetes supplies a root (no host dir to mount)."""
    _, extra = _isolate_trust
    _, organization = _write_ca(extra, "k8s-root")

    assert organization in _organizations(_build().context)


def test_given_both_directories_then_every_root_is_trusted(
    _isolate_trust: tuple[Path, Path],
) -> None:
    host_ca, extra = _isolate_trust
    _, from_host = _write_ca(host_ca, "host-root")
    _, from_mount = _write_ca(extra, "drop-in-root")

    organizations = _organizations(_build().context)

    assert {from_host, from_mount} <= organizations


def test_given_dangling_symlinks_then_the_real_bundle_loads_and_nothing_is_logged(
    _isolate_trust: tuple[Path, Path], caplog: pytest.LogCaptureFixture
) -> None:
    """A mounted /etc/ssl/certs is one real bundle plus ~150 symlinks into a directory that was
    not mounted. Every one of those dangles inside the container, and warning about each would
    bury the line an operator actually needs."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "real-root")
    for index in range(5):
        (host_ca / f"{index:08x}.0").symlink_to("/usr/share/ca-certificates/nowhere.crt")

    with caplog.at_level(logging.WARNING, logger="ares.agent.tls"):
        trust = _build()

    assert organization in _organizations(trust.context)
    assert [path.name for path in trust.loaded] == ["real-root.crt"]
    assert trust.rejected == ()
    assert caplog.records == []


def test_given_a_malformed_ca_then_it_is_reported_and_the_valid_one_still_loads(
    _isolate_trust: tuple[Path, Path], caplog: pytest.LogCaptureFixture
) -> None:
    """Unlike a dangling symlink, a file the operator meant us to trust is worth a warning; it
    must not cost us the rest of the bundle."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "good-root")
    (host_ca / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nnot a certificate\n")

    with caplog.at_level(logging.WARNING, logger="ares.agent.tls"):
        trust = _build()

    assert organization in _organizations(trust.context)
    assert [path.name for path in trust.rejected] == ["broken.pem"]
    assert "broken.pem" in caplog.text
    assert "broken.pem" in trust.summary()


def test_given_ares_ca_bundle_as_a_file_then_it_is_trusted(tmp_path: Path) -> None:
    path, organization = _write_ca(tmp_path / "elsewhere", "bundle-file-root")

    trust = _build(ca_bundle=str(path))

    assert organization in _organizations(trust.context)


def test_given_ares_ca_bundle_as_a_directory_then_every_pem_inside_is_trusted(
    tmp_path: Path,
) -> None:
    """Operators reasonably expect either, and guessing wrong should not fail silently."""
    directory = tmp_path / "bundle-dir"
    _, first = _write_ca(directory, "dir-root-a")
    _, second = _write_ca(directory, "dir-root-b")

    organizations = _organizations(_build(ca_bundle=str(directory)).context)

    assert {first, second} <= organizations


def test_given_insecure_then_verification_is_off_and_the_summary_says_so() -> None:
    trust = _build(insecure=True)

    assert not trust.verifies
    assert trust.context.verify_mode == ssl.CERT_NONE
    assert not trust.context.check_hostname
    assert "DISABLED" in trust.summary()


def test_given_a_certificate_error_then_the_hint_names_the_remedy() -> None:
    """The raw OpenSSL string says what happened and nothing about what to do. That gap is what
    turned a five-minute mount into a week of email."""
    error = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
    wrapped = ConnectionError("cannot connect")
    wrapped.__cause__ = error

    hint = _hint(wrapped)

    assert "inspecting TLS" in hint
    assert "/certs" in hint
    assert "Trust loaded:" in hint


def test_given_an_ordinary_connection_error_then_there_is_no_hint() -> None:
    """Appended unconditionally by the caller, so it has to stay empty for a plain timeout."""
    assert _hint(TimeoutError("timed out")) == ""


def test_given_a_self_referential_cause_chain_then_the_hint_terminates() -> None:
    """__cause__ chains can loop; walking one must not hang the agent's error path."""
    first = ConnectionError("a")
    second = ConnectionError("b")
    first.__cause__ = second
    second.__cause__ = first

    assert _hint(first) == ""


def test_the_control_plane_client_verifies_with_the_shared_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression guard for the actual bug. `verify=True` sends httpx to certifi's bundle
    inside site-packages, so a root CA installed in the container does nothing. Asserted on the
    argument we pass, which is the thing that has to stay right, rather than on httpcore
    internals that are free to move."""
    captured: dict[str, object] = {}

    def _record(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(control_plane.httpx, "AsyncClient", _record)
    control_plane._client(Settings(token="t", url="https://ares.example.com"))

    assert captured["verify"] is tlsconf.build_trust(insecure=False, ca_bundle="").context
    assert captured["verify"] is not True  # the bug, spelled out


def test_the_tunnel_takes_a_context_rather_than_building_its_own() -> None:
    """Control plane and data plane must verify against the same CAs; two independently built
    contexts is how they silently drift apart."""
    from agent.tunnel import TunnelClient

    context = _build().context
    client = TunnelClient("wss://x/api/v1/agent/tunnel", "tok", [], set(), ssl_context=context)

    assert client._ssl_context is context
