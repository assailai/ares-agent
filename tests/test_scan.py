"""Portable scanner: an open TCP port on a host shows up as a discovery."""

from __future__ import annotations

import asyncio

import pytest

from agent.scan import scan_cidr


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
