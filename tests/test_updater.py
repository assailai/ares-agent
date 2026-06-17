"""Companion updater: tag parsing, target read, the signature gate, and the apply backends."""

from __future__ import annotations

import json

import httpx
import pytest

from updater import dockerd, kube, main, verify
from updater.config import UpdaterSettings, tag_of


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


def test_tag_parsing_and_image_ref() -> None:
    assert tag_of("ghcr.io/assailai/ares-agent:2.5.0") == "2.5.0"
    assert tag_of("ghcr.io/assailai/ares-agent") == ""  # no tag
    assert tag_of("reg:5000/ares-agent") == ""  # registry port is not a tag
    assert _settings().image_for("2.5.0") == "ghcr.io/assailai/ares-agent:2.5.0"


def test_read_target(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "update-target.json"
    monkeypatch.setattr(main, "settings", _settings(target_file=target))
    assert main._read_target() is None  # not written yet
    target.write_text('{"version": "2.5.0"}')
    assert main._read_target() == "2.5.0"


def test_verify_gate() -> None:
    # dev override returns True (with a warning); fail-closed when on but unconfigured.
    assert verify.verify("img:1", UpdaterSettings(require_signature=False)) is True
    assert verify.verify("img:1", UpdaterSettings(require_signature=True)) is False


def test_docker_running_version(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Config": {"Image": "ghcr.io/assailai/ares-agent:2.4.0"}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    assert dockerd.running_version(_settings()) == "2.4.0"


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

    dockerd.apply(_settings(), "ghcr.io/assailai/ares-agent:2.5.0")

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
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://k8s")
    monkeypatch.setattr(kube, "_client", lambda: client)
    monkeypatch.setattr(kube, "_namespace", lambda _s: "default")

    kube.apply(_settings(), "ghcr.io/assailai/ares-agent:2.5.0")
    container = json.loads(seen["body"])["spec"]["template"]["spec"]["containers"][0]
    assert container == {"name": "ares-agent", "image": "ghcr.io/assailai/ares-agent:2.5.0"}


def test_tick_applies_only_on_verified_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    applied: list[str] = []

    class _Backend:
        def running_version(self, _s) -> str:
            return "2.4.0"

        def apply(self, _s, image: str) -> None:
            applied.append(image)

    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    main._tick(_Backend())
    assert applied == ["ghcr.io/assailai/ares-agent:2.5.0"]
