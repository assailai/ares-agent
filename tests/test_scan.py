"""Portable scanner: two-phase host discovery, chunking, and live progress/streaming.

Most tests drive a fake ``_connect`` so the topology (which host:port is open / refused / dead)
is deterministic and independent of whatever happens to listen on the test machine.
"""

from __future__ import annotations

import asyncio

import pytest

from agent import scan
from agent.scan import scan_cidr


def _fake_connect(topology: dict[tuple[str, int], str], *, probed: list[tuple[str, int]] | None = None):
    """A ``scan._connect`` replacement returning a scripted state per (ip, port).

    ``topology`` maps (ip, port) -> "open" | "closed"; anything absent is "down". When ``probed``
    is supplied, every attempted (ip, port) is appended so a test can assert what got probed.
    """

    async def _connect(ip: str, port: int, timeout: float) -> str:
        if probed is not None:
            probed.append((ip, port))
        return topology.get((ip, port), "down")

    return _connect


# --- real-socket smoke tests (the original behavioural contract) --------------------------------


@pytest.mark.asyncio
async def test_scan_detects_an_open_port() -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        hits = await scan_cidr("127.0.0.1/32", [port], timeout=1.0)
    finally:
        server.close()
        await server.wait_closed()

    assert len(hits) == 1
    assert hits[0]["ip"] == "127.0.0.1"
    assert hits[0]["port"] == port
    assert hits[0]["protocol"] == "tcp"


@pytest.mark.asyncio
async def test_scan_reports_nothing_on_a_closed_port() -> None:
    # port 1 is virtually never listening on loopback.
    assert await scan_cidr("127.0.0.1/32", [1], timeout=0.5) == []


# --- two-phase behaviour ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dead_hosts_are_not_port_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    # 10.0.0.1 answers (port 80 open); 10.0.0.2 is silent. The full port sweep must touch the live
    # host only -- the dead host costs a handful of discovery probes and nothing more.
    probed: list[tuple[str, int]] = []
    topology = {("10.0.0.1", 80): "open", ("10.0.0.1", 3306): "open"}
    monkeypatch.setattr(scan, "_connect", _fake_connect(topology, probed=probed))

    hits = await scan_cidr("10.0.0.0/30", [80, 3306, 5432])

    hit_keys = {(h["ip"], h["port"]) for h in hits}
    assert hit_keys == {("10.0.0.1", 80), ("10.0.0.1", 3306)}
    # the live host was swept for the requested non-discovery ports...
    assert ("10.0.0.1", 3306) in probed and ("10.0.0.1", 5432) in probed
    # ...but the dead host was never swept for them.
    assert ("10.0.0.2", 3306) not in probed and ("10.0.0.2", 5432) not in probed


@pytest.mark.asyncio
async def test_refused_port_counts_as_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    # a refused (RST) discovery port means the host is up even though nothing is listening there,
    # so the host is still port-swept.
    probed: list[tuple[str, int]] = []
    topology = {("10.0.0.1", 22): "closed"}  # refused, not open
    monkeypatch.setattr(scan, "_connect", _fake_connect(topology, probed=probed))

    hits = await scan_cidr("10.0.0.1/32", [3306])

    assert hits == []  # nothing was actually open
    assert ("10.0.0.1", 3306) in probed  # but liveness (via refused) triggered the sweep


@pytest.mark.asyncio
async def test_unreachable_host_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    probed: list[tuple[str, int]] = []
    monkeypatch.setattr(scan, "_connect", _fake_connect({}, probed=probed))  # everything "down"

    hits = await scan_cidr("10.0.0.1/32", [3306])

    assert hits == []
    assert ("10.0.0.1", 3306) not in probed  # a dead host is never swept


@pytest.mark.asyncio
async def test_open_discovery_port_reported_only_when_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 8080 is a discovery port. It drives liveness always, but is a *finding* only when requested.
    topology = {("10.0.0.1", 8080): "open"}
    monkeypatch.setattr(scan, "_connect", _fake_connect(topology))

    without = await scan_cidr("10.0.0.1/32", [3306])
    with_it = await scan_cidr("10.0.0.1/32", [3306, 8080])

    assert without == []  # 8080 open but not requested -> liveness only, not reported
    assert {(h["ip"], h["port"]) for h in with_it} == {("10.0.0.1", 8080)}


# --- chunking + progress + streaming ------------------------------------------------------------


def test_plan_chunks_splits_and_caps() -> None:
    chunks, total = scan._plan_chunks("10.0.0.0/16", chunk_prefix=24, max_hosts=10**9)
    assert len(chunks) == 256
    assert total == 256 * 254

    capped_chunks, capped_total = scan._plan_chunks("10.0.0.0/16", chunk_prefix=24, max_hosts=500)
    assert len(capped_chunks) == 1  # a second /24 would exceed 500 hosts
    assert capped_total == 254


@pytest.mark.asyncio
async def test_finds_live_hosts_across_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    # one live host in each /24 of a /23 -- both must be found when the range is chunked.
    topology = {("10.0.0.5", 80): "open", ("10.0.1.5", 80): "open"}
    monkeypatch.setattr(scan, "_connect", _fake_connect(topology))

    hits = await scan_cidr("10.0.0.0/23", [80], chunk_prefix=24)

    assert {(h["ip"], h["port"]) for h in hits} == {("10.0.0.5", 80), ("10.0.1.5", 80)}


@pytest.mark.asyncio
async def test_progress_is_monotonic_and_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    topology = {("10.0.0.5", 80): "open"}
    monkeypatch.setattr(scan, "_connect", _fake_connect(topology))
    seen: list[int] = []

    async def _on_progress(pct: int) -> None:
        seen.append(pct)

    await scan_cidr("10.0.0.0/24", [80], on_progress=_on_progress)

    assert seen == sorted(seen)  # never goes backwards
    assert seen[-1] == 100  # always finishes at 100
    assert all(0 <= p <= 100 for p in seen)


@pytest.mark.asyncio
async def test_streamed_hosts_union_to_final_result(monkeypatch: pytest.MonkeyPatch) -> None:
    topology = {("10.0.0.5", 80): "open", ("10.0.1.7", 80): "open"}
    monkeypatch.setattr(scan, "_connect", _fake_connect(topology))
    streamed: list[dict] = []

    async def _on_hosts(chunk: list[dict]) -> None:
        streamed.extend(chunk)

    final = await scan_cidr("10.0.0.0/23", [80], chunk_prefix=24, on_hosts=_on_hosts)

    streamed_keys = {(h["ip"], h["port"]) for h in streamed}
    final_keys = {(h["ip"], h["port"]) for h in final}
    assert streamed_keys == final_keys  # everything reported live also appears in the final list
    assert len(streamed) == len(final)  # and nothing was streamed twice


@pytest.mark.asyncio
async def test_budget_stops_scanning_early(monkeypatch: pytest.MonkeyPatch) -> None:
    # a zero-second budget means the very first chunk boundary check trips: no chunk runs.
    probed: list[tuple[str, int]] = []
    monkeypatch.setattr(scan, "_connect", _fake_connect({("10.0.0.5", 80): "open"}, probed=probed))

    hits = await scan_cidr("10.0.0.0/16", [80], budget_seconds=0.0)

    assert hits == []
    assert probed == []  # budget exhausted before any probing began
