"""Self-update launches a one-shot Watchtower over the Docker socket, and only when safe."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from agent.config import Settings
from agent.selfupdate import _launch_watchtower, trigger_self_update


def _settings() -> Settings:
    return Settings(container_name="ares-agent", watchtower_image="containrrr/watchtower:latest")


def test_launch_watchtower_pulls_then_creates_and_starts() -> None:
    # the agent pulls Watchtower, creates a one-shot updater targeting its own container, starts it.
    calls: list[tuple[str, str]] = []
    create_body: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            create_body.update(json.loads(request.content))
            return httpx.Response(201, json={"Id": "watch123"})
        return httpx.Response(200, text="")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://docker")

    async def run() -> None:
        async with client:
            await _launch_watchtower(client, _settings())

    asyncio.run(run())

    assert ("POST", "/images/create") in calls  # pull Watchtower first
    assert ("POST", "/containers/create") in calls
    assert ("POST", "/containers/watch123/start") in calls
    assert create_body["Cmd"] == ["--run-once", "ares-agent"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in create_body["HostConfig"]["Binds"]


def test_trigger_is_a_safe_noop_without_the_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    # with the socket absent, self-update refuses (returns False) rather than crashing the agent.
    monkeypatch.setattr("agent.selfupdate.socket_available", lambda: False)
    assert asyncio.run(trigger_self_update(_settings())) is False
