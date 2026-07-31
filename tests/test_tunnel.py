"""Data-plane tunnel client: URL derivation, frame codec, destination authorization (IP
literals against the registered networks, hostnames resolved here and checked either way),
and OPEN-frame resilience (a bad or out-of-scope target is refused, never a crash)."""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

from agent.tunnel import (
    _DATA,
    _HOSTS_REPORTED_MAX,
    _OPEN_ERR,
    RefusalLog,
    Refused,
    TunnelClient,
    TunnelManager,
    _decode,
    _encode,
    normalize_host,
    summarize_addresses,
    tunnel_url,
)


class _RecordingWS:
    """Stands in for a live WebSocket, capturing the frames the client sends."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)


def _client(
    networks: list[str] | None = None, allowed_hosts: set[str] | None = None
) -> TunnelClient:
    return TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        networks if networks is not None else ["10.0.0.0/24", "192.168.1.0/24"],
        allowed_hosts if allowed_hosts is not None else set(),
        ssl_context=None,
    )


def _stub_resolver(client: TunnelClient, mapping: dict[str, list[str]]) -> None:
    """Resolve names from ``mapping`` instead of touching real DNS; unknown names fail."""

    async def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise Refused(f"{host} did not resolve on this agent")
        return mapping[host]

    client._resolve = resolve  # type: ignore[method-assign]


def test_tunnel_url_maps_scheme_and_path() -> None:
    assert tunnel_url("https://api.assailai.com") == "wss://api.assailai.com/api/v1/agent/tunnel"
    assert (
        tunnel_url("http://host.docker.internal:8000/")
        == "ws://host.docker.internal:8000/api/v1/agent/tunnel"
    )


def test_frame_round_trips() -> None:
    assert _decode(_encode(_DATA, 7, b"hello")) == (_DATA, 7, b"hello")


def test_normalize_host_is_case_and_root_dot_insensitive() -> None:
    assert normalize_host("Bank.Internal.") == "bank.internal"
    assert normalize_host("  bank.internal ") == "bank.internal"


# ── IP literals: unchanged behaviour ──────────────────────────────────────────
def test_ip_inside_registered_networks_is_dialed_as_is() -> None:
    client = _client()
    assert asyncio.run(client._dial_address("10.0.0.5", 80)) == "10.0.0.5"
    assert asyncio.run(client._dial_address("192.168.1.200", 443)) == "192.168.1.200"


def test_ip_outside_registered_networks_is_refused() -> None:
    client = _client()
    with pytest.raises(Refused):
        asyncio.run(client._dial_address("8.8.8.8", 53))


# ── hostnames: resolved here, then authorized ─────────────────────────────────
def test_name_resolving_into_registered_networks_is_allowed() -> None:
    client = _client()
    _stub_resolver(client, {"bank.internal": ["10.0.0.7"]})
    assert asyncio.run(client._dial_address("bank.internal", 8000)) == "10.0.0.7"


def test_name_resolving_outside_networks_is_refused_without_a_pushed_host() -> None:
    client = _client()
    _stub_resolver(client, {"staging.acme.com": ["203.0.113.10"]})
    with pytest.raises(Refused, match="not an approved target"):
        asyncio.run(client._dial_address("staging.acme.com", 443))


def test_pushed_host_allows_a_name_outside_the_networks() -> None:
    client = _client(allowed_hosts={"staging.acme.com"})
    _stub_resolver(client, {"staging.acme.com": ["203.0.113.10"]})
    assert asyncio.run(client._dial_address("staging.acme.com", 443)) == "203.0.113.10"


def test_pushed_host_match_ignores_case_and_root_dot() -> None:
    client = _client(allowed_hosts={"staging.acme.com"})
    _stub_resolver(client, {"Staging.Acme.com.": ["203.0.113.10"]})
    assert asyncio.run(client._dial_address("Staging.Acme.com.", 443)) == "203.0.113.10"


def test_a_name_is_refused_once_its_host_leaves_the_pushed_set() -> None:
    # the set is shared with the manager and mutated in place, so a hunt ending closes the door
    # on the live connection without a reconnect.
    hosts = {"staging.acme.com"}
    client = _client(allowed_hosts=hosts)
    _stub_resolver(client, {"staging.acme.com": ["203.0.113.10"]})
    assert asyncio.run(client._dial_address("staging.acme.com", 443)) == "203.0.113.10"
    hosts.clear()
    with pytest.raises(Refused):
        asyncio.run(client._dial_address("staging.acme.com", 443))


def test_a_name_with_any_address_outside_the_networks_needs_the_pushed_set() -> None:
    # a split answer must not sneak past on the strength of one in-network address.
    client = _client()
    _stub_resolver(client, {"mixed.internal": ["10.0.0.7", "8.8.8.8"]})
    with pytest.raises(Refused):
        asyncio.run(client._dial_address("mixed.internal", 80))


def test_unresolvable_name_is_refused() -> None:
    client = _client()
    _stub_resolver(client, {})
    with pytest.raises(Refused, match="did not resolve"):
        asyncio.run(client._dial_address("nowhere.internal", 80))


def test_resolve_deduplicates_and_preserves_order() -> None:
    client = _client()

    async def fake_getaddrinfo(host: str, port: int, **kwargs: object) -> list[tuple]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", port)),
        ]

    async def run() -> list[str]:
        asyncio.get_running_loop().getaddrinfo = fake_getaddrinfo  # type: ignore[method-assign]
        return await client._resolve("bank.internal", 8000)

    assert asyncio.run(run()) == ["10.0.0.7", "10.0.0.8"]


def test_unparseable_address_is_never_treated_as_inside_the_networks() -> None:
    client = _client(networks=["10.0.0.0/8", "fe80::/10"])
    assert client._in_allowed_networks("not-an-address") is False
    # a scope id is legal and still compared on the address itself.
    assert client._in_allowed_networks("fe80::1%eth0") is True


# ── OPEN-frame handling ───────────────────────────────────────────────────────
def _client_with_ws(allowed_hosts: set[str] | None = None) -> tuple[TunnelClient, _RecordingWS]:
    client = _client(["10.0.0.0/24"], allowed_hosts)
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


def test_open_with_an_unauthorized_name_is_refused() -> None:
    client, ws = _client_with_ws()
    _stub_resolver(client, {"evil.example.com": ["203.0.113.10"]})
    asyncio.run(client._open(11, json.dumps({"host": "evil.example.com", "port": 80}).encode()))
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 11)


def test_open_dials_the_resolved_address_not_the_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # the check and the connect must land on the same destination, so the dial uses the address
    # we authorized rather than going back through the resolver.
    client, ws = _client_with_ws({"bank.internal"})
    _stub_resolver(client, {"bank.internal": ["203.0.113.10"]})
    dialed: list[tuple[str, int]] = []

    async def fake_open_connection(host: str, port: int):
        dialed.append((host, port))
        raise OSError("no listener in the test")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    asyncio.run(client._open(13, json.dumps({"host": "bank.internal", "port": 8000}).encode()))
    assert dialed == [("203.0.113.10", 8000)]
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 13)  # the dial failed, so the stream fails


# ── manager: the pushed set ───────────────────────────────────────────────────
def test_manager_sync_replaces_the_pushed_host_set_in_place() -> None:
    manager = TunnelManager("ws://x", "tok", ["10.0.0.0/24"], ssl_context=None)
    shared = manager._allowed_hosts
    manager.sync(False, ["Bank.Internal.", "  ", "staging.acme.com"])
    assert shared == {"bank.internal", "staging.acme.com"}
    manager.sync(False, [])
    assert shared == set()
    assert shared is manager._allowed_hosts  # the live client holds this same object


# ── refusal logging: readable at hundreds-per-run volumes ─────────────────────
def test_summarize_addresses_names_a_few_then_counts_the_rest() -> None:
    assert summarize_addresses(["1.1.1.1", "2.2.2.2"]) == "1.1.1.1, 2.2.2.2"
    many = [f"10.0.0.{n}" for n in range(1, 9)]
    assert summarize_addresses(many) == "10.0.0.1, 10.0.0.2, 10.0.0.3, +5 more"


def test_a_refused_host_is_explained_once_then_only_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One assessment refuses the same telemetry host hundreds of times; a per-dial WARNING would
    bury the refusal an operator actually needs to see."""
    log = RefusalLog()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        for _ in range(50):
            log.record("autofill.example.com", "autofill.example.com resolves outside ...")
        log.record("other.example.com", "other.example.com resolves outside ...")

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 2  # one per host, not one per dial
        assert not [r for r in caplog.records if r.levelname == "INFO"]  # rollup not due yet

        caplog.clear()
        log.flush()
        rollup = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]

    assert len(rollup) == 1
    assert "49 further tunnel dial(s) to 1 host(s)" in rollup[0]
    assert "autofill.example.com x49" in rollup[0]


def test_flush_is_quiet_when_nothing_was_suppressed(caplog: pytest.LogCaptureFixture) -> None:
    log = RefusalLog()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        log.record("one.example.com", "one.example.com resolves outside ...")
        caplog.clear()
        log.flush()
        log.flush()
    assert caplog.records == []  # no empty rollups, and no re-explaining a reported host


def test_open_records_the_refusal_once_per_host(caplog: pytest.LogCaptureFixture) -> None:
    """The OPEN path must route refusals through the collapsing log, not straight to a WARNING."""
    client = _client()
    client._ws = _RecordingWS()  # type: ignore[assignment]
    _stub_resolver(client, {"evil.example.com": ["8.8.8.8"]})
    frame = json.dumps({"host": "evil.example.com", "port": 80}).encode()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        for stream_id in range(5):
            asyncio.run(client._open(stream_id, frame))

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "not an approved target" in warnings[0].getMessage()


def test_full_refusal_lines_are_capped_across_distinct_hosts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The page under test decides what the browser dials, so distinct refused hosts are not ours to
    bound: one referencing a thousand third parties must not produce a thousand WARNING lines."""
    log = RefusalLog()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        for n in range(_HOSTS_REPORTED_MAX * 2):
            log.record(f"host{n}.example.com", f"host{n}.example.com resolves outside ...")

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == _HOSTS_REPORTED_MAX  # the rest are counted, not printed

    caplog.clear()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        log.flush()
    rollup = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
    assert len(rollup) == 1
    assert f"to {_HOSTS_REPORTED_MAX} host(s)" in rollup[0]  # the ones over budget still accounted
