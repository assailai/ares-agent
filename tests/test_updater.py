"""Companion updater: image-ref parsing, target read, the signature gate, and the backends."""

from __future__ import annotations

import json
import types

import httpx
import pytest

from updater import dockerd, kube, main, verify
from updater.config import UpdaterSettings, repo_of, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


@pytest.fixture(autouse=True)
def _clear_verified_cache():
    # the verified-digest cache is a module global; isolate it between tests.
    main._verified.clear()
    yield


def test_container_name_reads_the_documented_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # the docs / compose / k8s use ARES_UPDATE_CONTAINER; it must actually set container_name
    # (reading only the *_NAME alias was a silent-misconfig bug).
    monkeypatch.setenv("ARES_UPDATE_CONTAINER", "custom-agent")
    assert _settings().container_name == "custom-agent"


def test_image_ref_parsing() -> None:
    assert tag_of("assailai/ares-agent:2.5.0") == "2.5.0"
    assert repo_of("assailai/ares-agent:2.5.0") == "assailai/ares-agent"
    assert tag_of("assailai/ares-agent") == ""  # no tag
    assert repo_of("reg:5000/ares-agent") == "reg:5000/ares-agent"  # the ":" is a registry port
    assert repo_of("assailai/ares-agent@sha256:abc123") == "assailai/ares-agent"  # digest ref
    assert tag_of("assailai/ares-agent@sha256:abc123") == ""  # a digest is not a tag


def test_read_target(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "update-target.json"
    monkeypatch.setattr(main, "settings", _settings(target_file=target))
    assert main._read_target() is None  # not written yet
    target.write_text('{"version": "2.5.0"}')
    assert main._read_target() == "2.5.0"
    target.write_text("not json")  # malformed is ignored, not crashed on
    assert main._read_target() is None


def test_verify_gate() -> None:
    # dev override returns the ref unpinned (with a warning); fail-closed (None) when on but
    # unconfigured (no cosign key or identity).
    assert verify.verify("img:1", UpdaterSettings(require_signature=False)) == "img:1"
    assert verify.verify("img:1", UpdaterSettings(require_signature=True)) is None


def test_verify_pins_the_cosign_verified_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    # cosign resolves the tag and attests a digest; verify returns that exact digest pinned to
    # the repo, so the caller applies the verified content rather than re-resolving the tag.
    payload = '[{"critical": {"image": {"docker-manifest-digest": "sha256:abc123"}}}]'
    monkeypatch.setattr(
        verify.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=payload, stderr=""),
    )
    pinned = verify.verify(
        "assailai/ares-agent:3.0.0",
        UpdaterSettings(require_signature=True, cosign_identity="^id$", cosign_issuer="iss"),
    )
    assert pinned == "assailai/ares-agent@sha256:abc123"


def test_docker_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Config": {"Image": "assailai/ares-agent:2.4.0"}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    assert DockerBackend().running_image(_settings()) == "assailai/ares-agent:2.4.0"


def test_docker_apply_verifies_new_then_swaps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            return httpx.Response(201, json={"Id": "new123"})
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={"Config": {}, "HostConfig": {}, "State": {"Running": True}})
        return httpx.Response(200, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
    monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    DockerBackend().apply(_settings(), "assailai/ares-agent:2.5.0")

    # pulled, created the replacement, started it, then removed the old and renamed the new in.
    assert ("POST", "/images/create") in calls
    assert ("POST", "/containers/create") in calls
    assert ("POST", "/containers/new123/start") in calls
    assert ("DELETE", "/containers/ares-agent") in calls
    assert ("POST", "/containers/new123/rename") in calls


def test_k8s_apply_patches_the_deployment_image(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            seen["body"] = request.read().decode()
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://k8s")
    monkeypatch.setattr(kube, "_client", lambda: client)
    monkeypatch.setattr(kube, "_namespace", lambda _s: "default")

    K8sBackend().apply(_settings(), "assailai/ares-agent:2.5.0")
    container = json.loads(seen["body"])["spec"]["template"]["spec"]["containers"][0]
    assert container == {"name": "ares-agent", "image": "assailai/ares-agent:2.5.0"}


class _FakeBackend:
    """Stand-in backend that records what it was asked to apply."""

    def __init__(self, running: str | None) -> None:
        self.running = running
        self.applied: str | None = None

    def available(self) -> bool:
        return True

    def running_image(self, settings: UpdaterSettings) -> str | None:
        return self.running

    def apply(self, settings: UpdaterSettings, image_ref: str) -> None:
        self.applied = image_ref


def test_tick_derives_repo_from_the_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())  # image_repo unset -> derive
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == "assailai/ares-agent:2.5.0"


def test_tick_noop_when_already_on_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.5.0")
    main._tick(backend)
    assert backend.applied is None


def test_tick_applies_the_verified_digest_then_noops(monkeypatch: pytest.MonkeyPatch) -> None:
    # the tick applies the DIGEST verify returned (not the tag), closing the TOCTOU; once the
    # agent runs that digest, the cache makes a re-tick a noop (no churn, no re-verify).
    monkeypatch.setattr(main, "settings", _settings())  # verify is mocked below, so the gate is moot
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    pinned = "assailai/ares-agent@sha256:abc123"
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: pinned)

    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == pinned  # the verified digest, not the 2.5.0 tag

    backend.running, backend.applied = pinned, None  # agent now runs the pinned digest
    main._tick(backend)
    assert backend.applied is None  # cache hit -> no re-apply
