"""Data-plane tunnel client: URL derivation, frame codec, the target allowlist, and
OPEN-frame resilience (a bad or out-of-scope target is refused, never a crash)."""

from __future__ import annotations

import asyncio
import json

from agent.tunnel import _DATA, _OPEN_ERR, TunnelClient, _decode, _encode, tunnel_url


class _RecordingWS:
    """Stands in for a live WebSocket, capturing the frames the client sends."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)


def test_tunnel_url_maps_scheme_and_path() -> None:
    assert tunnel_url("https://api.assailai.com") == "wss://api.assailai.com/api/v1/agent/tunnel"
    assert (
        tunnel_url("http://host.docker.internal:8000/")
        == "ws://host.docker.internal:8000/api/v1/agent/tunnel"
    )


def test_frame_round_trips() -> None:
    assert _decode(_encode(_DATA, 7, b"hello")) == (_DATA, 7, b"hello")


def test_target_allowlist_only_permits_registered_ranges() -> None:
    client = TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        ["10.0.0.0/24", "192.168.1.0/24"],
        insecure=False,
    )
    assert client._target_allowed("10.0.0.5") is True
    assert client._target_allowed("192.168.1.200") is True
    assert client._target_allowed("8.8.8.8") is False  # outside the agent's networks
    assert client._target_allowed("evil.example.com") is False  # names are never resolved


def _client_with_ws() -> tuple[TunnelClient, _RecordingWS]:
    client = TunnelClient("ws://x/api/v1/agent/tunnel", "tok", ["10.0.0.0/24"], insecure=False)
    ws = _RecordingWS()
    client._ws = ws
    return client, ws


def test_malformed_open_frame_is_refused_not_fatal() -> None:
    # a garbled OPEN payload answers OPEN_ERR (so ares fails that stream fast) and never raises.
    client, ws = _client_with_ws()
    asyncio.run(client._open(5, b"not json at all"))
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 5)


def test_open_outside_allowlist_is_refused() -> None:
    # a target the agent was never registered for is refused at OPEN.
    client, ws = _client_with_ws()
    asyncio.run(client._open(9, json.dumps({"host": "8.8.8.8", "port": 53}).encode()))
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 9)
