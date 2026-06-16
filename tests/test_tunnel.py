"""Data-plane tunnel client: URL derivation, frame codec, and the target allowlist."""

from __future__ import annotations

from agent.tunnel import _DATA, TunnelClient, _decode, _encode, tunnel_url


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
