"""Companion updater: image-ref parsing, target read, the signature gate, and the backends."""

from __future__ import annotations

import json

import httpx
import pytest

from updater import dockerd, kube, main, verify
from updater.config import UpdaterSettings, repo_of, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


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


def test_read_target(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "update-target.json"
    monkeypatch.setattr(main, "settings", _settings(target_file=target))
    assert main._read_target() is None  # not written yet
    target.write_text('{"version": "2.5.0"}')
    assert main._read_target() == "2.5.0"
    target.write_text("not json")  # malformed is ignored, not crashed on
    assert main._read_target() is None


def test_verify_gate() -> None:
    # dev override returns True (with a warning); fail-closed when on but unconfigured.
    assert verify.verify("img:1", UpdaterSettings(require_signature=False)) is True
    assert verify.verify("img:1", UpdaterSettings(require_signature=True)) is False


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
