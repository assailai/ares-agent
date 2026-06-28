"""Portable async TCP-connect scanner for ``local_network_scan`` tasks.

Deliberately dependency-free (no masscan, no root, no raw sockets) so the agent runs
anywhere a container can, and so the control-plane loop is testable on a laptop. It
connects to each host:port in the target CIDR; an open port is a discovered service.
Host count and concurrency are bounded so a /24 stays quick.
"""

from __future__ import annotations

import asyncio
import ipaddress

DEFAULT_PORTS = (80, 443, 8080, 8443)
MAX_HOSTS = 1024  # safety cap; larger ranges are chunked server-side

_COMMON_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


def _service_for(port: int) -> str:
    return _COMMON_SERVICES.get(port, "unknown")


async def _probe(ip: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.close()
        await writer.wait_closed()
    except OSError:
        pass
    return {
        "ip": ip,
        "port": port,
        "service": _service_for(port),
        "protocol": "tcp",
        "evidence": f"tcp connect succeeded on {ip}:{port}",
    }


async def scan_cidr(
    cidr: str,
    ports: list[int] | None = None,
    *,
    timeout: float = 2.0,
    concurrency: int = 256,
    max_hosts: int = MAX_HOSTS,
) -> list[dict]:
    """Return discovered ``{ip, port, service, protocol, evidence}`` for open ports in ``cidr``."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()][:max_hosts]
    if not hosts:  # a bare host address (/32) has no "hosts"; scan it directly.
        hosts = [str(network.network_address)]
    targets = ports or list(DEFAULT_PORTS)

    semaphore = asyncio.Semaphore(concurrency)
    discovered: list[dict] = []

    async def _one(ip: str, port: int) -> None:
        async with semaphore:
            hit = await _probe(ip, port, timeout)
        if hit is not None:
            discovered.append(hit)

    await asyncio.gather(*(_one(ip, port) for ip in hosts for port in targets))
    discovered.sort(key=lambda d: (d["ip"], d["port"]))
    return discovered
