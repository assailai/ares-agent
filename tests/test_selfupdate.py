"""Self-update launches the recreate helper over the Docker socket, and only when safe."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from agent.config import Settings
from agent.selfupdate import _launch_updater, trigger_self_update
from agent.updater import target_image


def test_target_image_swaps_only_the_tag() -> None:
    assert (
        target_image("ghcr.io/assailai/ares-agent:2.4.0", "2.5.0")
        == "ghcr.io/assailai/ares-agent:2.5.0"
    )
    # no tag on the ref -> append the target
    assert target_image("ghcr.io/assailai/ares-agent", "2.5.0") == "ghcr.io/assailai/ares-agent:2.5.0"
    # a registry port is not a tag
    assert target_image("reg:5000/ares-agent", "2.5.0") == "reg:5000/ares-agent:2.5.0"


def test_launch_updater_creates_helper_with_swap_env_and_socket() -> None:
    calls: list[tuple[str, str]] = []
    create_body: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            create_body.update(json.loads(request.content))
            return httpx.Response(201, json={"Id": "upd123"})
        return httpx.Response(200, text="")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://docker")

    async def run() -> None:
        async with client:
            await _launch_updater(client, "ares-agent", "2.5.0", "ghcr.io/assailai/ares-agent:2.4.0")

    asyncio.run(run())

    assert ("POST", "/containers/create") in calls
    assert ("POST", "/containers/upd123/start") in calls
    # the helper runs the updater (not the agent) and gets the swap parameters + the socket.
    assert create_body["Entrypoint"] == ["python", "-m", "agent.updater"]
    assert "ARES_UPDATE_CONTAINER=ares-agent" in create_body["Env"]
    assert "ARES_UPDATE_TARGET=2.5.0" in create_body["Env"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in create_body["HostConfig"]["Binds"]


def test_trigger_is_a_safe_noop_without_the_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.selfupdate.socket_available", lambda: False)
    assert asyncio.run(trigger_self_update(Settings(), "2.5.0")) is False


def test_trigger_skips_when_no_target_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.selfupdate.socket_available", lambda: True)
    assert asyncio.run(trigger_self_update(Settings(), "")) is False
