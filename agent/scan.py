"""Portable async TCP-connect scanner for ``local_network_scan`` tasks.

Deliberately dependency-free (no masscan, no root, no raw sockets) so the agent runs
anywhere a container can, and so the control-plane loop is testable on a laptop.

It is two-phase, chunked, and streaming so it stays fast at /16 scale:

* the target CIDR is split into /24 chunks (bounded memory, incremental progress);
* **phase 1 (host discovery)** probes a few high-signal ports across every host in a chunk to
  learn which hosts are alive -- a port that *connects* or is *refused* means the host answered,
  a timeout / unreachable means it did not;
* **phase 2 (port sweep)** probes the full port list only against the hosts phase 1 found alive.

Dead hosts -- the bulk of any large range -- are dropped after a handful of short probes instead
of the full port list, so a /24 finishes in seconds and a mostly-dead /16 in a couple of minutes.
Progress and discovered hosts are streamed through optional callbacks so the control plane can
show a live percentage and surface hosts as they are found.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable, Sequence

logger = logging.getLogger("ares.agent.scan")

# Curated top ~100 TCP ports: the services most worth knowing about on an internal network
# (web, databases, remote access, file shares, mail, message queues, admin panels). 3000 is
# included so OWASP Juice Shop and Grafana-style dev services are found out of the box.
TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 26, 37, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143, 161, 179, 199,
    389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 623, 631, 636, 873,
    902, 990, 993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2222, 2375,
    2376, 2379, 3000, 3128, 3268, 3306, 3389, 3690, 4444, 5000, 5432, 5601, 5672, 5900, 5984,
    5985, 5986, 6379, 6443, 7001, 8000, 8008, 8009, 8080, 8081, 8088, 8180, 8443, 8500, 8888,
    9000, 9042, 9092, 9200, 9300, 9418, 10000, 11211, 15672, 27017, 27018, 50000,
)
# Lean liveness set for phase 1: the ports most likely to answer on *some* host in a range.
DISCOVERY_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389, 8080)
# The port list a task sweeps when the control plane sends none (server usually overrides).
DEFAULT_PORTS: tuple[int, ...] = TOP_PORTS
# Hosts are scanned a /24 at a time: the natural unit, and small enough to bound memory.
CHUNK_PREFIX = 24
# Safety ceiling on hosts in a single task. A full /16 (~65k) is well within this; a scope that
# resolves to something enormous (e.g. an explicit 10/8) is truncated -- and *logged*, never
# silently -- rather than exhausting the box.
MAX_HOSTS = 262_144  # a /14
# Fast per-connect timeout for the phase-1 liveness sweep (dead hosts cost only this).
DEFAULT_DISCOVERY_TIMEOUT = 0.5

_COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
    548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi", 631: "ipp", 636: "ldaps",
    873: "rsync", 902: "vmware", 990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "java-rmi", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls", 2379: "etcd", 3000: "http-dev",
    3128: "squid", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 3690: "svn", 4444: "metasploit",
    5000: "http-alt", 5432: "postgres", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes-api",
    7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8009: "ajp", 8080: "http-proxy",
    8081: "http-alt", 8088: "http-alt", 8180: "http-alt", 8443: "https-alt", 8500: "consul",
    8888: "http-alt", 9000: "http-alt", 9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq",
    27017: "mongodb", 27018: "mongodb", 50000: "sap",
}

ProgressCallback = Callable[[int], Awaitable[None]]
HostsCallback = Callable[[list[dict]], Awaitable[None]]


def _service_for(port: int) -> str:
    return _COMMON_SERVICES.get(port, "unknown")


def _hit(ip: str, port: int) -> dict:
    return {
        "ip": ip,
        "port": port,
        "service": _service_for(port),
        "protocol": "tcp",
        "evidence": f"tcp connect succeeded on {ip}:{port}",
    }


async def _connect(ip: str, port: int, timeout: float) -> str:
    """Classify a single TCP connect attempt.

    ``"open"``   -- connected (a live service);
    ``"closed"`` -- refused via RST (the host is up, this port just isn't listening);
    ``"down"``   -- timed out or unreachable (no answer).

    Both ``open`` and ``closed`` prove the host is alive, which is what phase 1 needs.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return "down"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        # EHOSTUNREACH / ENETUNREACH / EADDRNOTAVAIL and friends: treat as no answer.
        return "down"
    try:
        writer.close()
        await writer.wait_closed()
    except OSError:
        pass
    return "open"


def _usable_count(net: ipaddress.IPv4Network) -> int:
    """How many host addresses a chunk actually scans (mirrors ``list(net.hosts())`` length)."""
    if net.prefixlen >= 31:  # /31 and /32 have no network/broadcast to exclude
        return net.num_addresses
    return net.num_addresses - 2


def _chunk_hosts(net: ipaddress.IPv4Network) -> list[str]:
    hosts = [str(h) for h in net.hosts()]
    if not hosts:  # a bare host address (/32) has no "hosts"; scan it directly.
        hosts = [str(net.network_address)]
    return hosts


def _plan_chunks(
    cidr: str, *, chunk_prefix: int, max_hosts: int
) -> tuple[list[ipaddress.IPv4Network], int]:
    """Split ``cidr`` into <= /``chunk_prefix`` chunks, capped at ``max_hosts`` total hosts.

    Returns ``(chunks, total_hosts)``. Truncation is logged, never silent.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError(f"only IPv4 ranges are supported, got {cidr}")
    if network.prefixlen < chunk_prefix:
        candidates: object = network.subnets(new_prefix=chunk_prefix)
    else:
        candidates = iter((network,))

    chunks: list[ipaddress.IPv4Network] = []
    total = 0
    for chunk in candidates:  # type: ignore[assignment]
        usable = max(_usable_count(chunk), 1)
        if total + usable > max_hosts:
            logger.warning(
                "%s exceeds the %d-host scan cap; scanning the first %d hosts only.",
                cidr,
                max_hosts,
                total,
            )
            break
        chunks.append(chunk)
        total += usable
    return chunks, total


async def scan_cidr(
    cidr: str,
    ports: Sequence[int] | None = None,
    *,
    timeout: float = 2.0,
    discovery_timeout: float | None = None,
    concurrency: int = 512,
    max_hosts: int = MAX_HOSTS,
    chunk_prefix: int = CHUNK_PREFIX,
    discovery_ports: Sequence[int] = DISCOVERY_PORTS,
    budget_seconds: float | None = None,
    on_progress: ProgressCallback | None = None,
    on_hosts: HostsCallback | None = None,
) -> list[dict]:
    """Return discovered ``{ip, port, service, protocol, evidence}`` for open ports in ``cidr``.

    Two-phase and chunked (see the module docstring). ``on_progress(percent)`` is invoked as the
    integer percentage climbs; ``on_hosts(chunk)`` streams newly discovered hosts as each chunk
    finishes. ``budget_seconds`` is an overall soft deadline: once exceeded, no new chunk starts
    and whatever was found so far is returned (partial, logged).
    """
    port_list = list(ports) if ports else list(DEFAULT_PORTS)
    requested = set(port_list)
    disc_list = list(discovery_ports)
    disc_set = set(disc_list)
    # Phase 2 sweeps the requested ports that phase 1 did not already probe. Discovery ports that
    # are *not* requested are used only for liveness -- they are never reported as findings.
    sweep_ports = [p for p in port_list if p not in disc_set]
    disc_timeout = (
        discovery_timeout if discovery_timeout is not None else min(timeout, DEFAULT_DISCOVERY_TIMEOUT)
    )
    semaphore = asyncio.Semaphore(max(1, concurrency))
    started = time.monotonic()

    chunks, total_hosts = _plan_chunks(cidr, chunk_prefix=chunk_prefix, max_hosts=max_hosts)
    total_hosts = max(total_hosts, 1)

    discovered: list[dict] = []
    done = 0
    last_pct = -1

    async def _bounded(ip: str, port: int, to: float) -> str:
        async with semaphore:
            return await _connect(ip, port, to)

    async def _emit_progress() -> None:
        nonlocal last_pct
        pct = min(100, int(done * 100 / total_hosts))
        if pct > last_pct:
            last_pct = pct
            if on_progress is not None:
                await on_progress(pct)

    async def _discover(ip: str) -> tuple[str, bool, list[dict]]:
        nonlocal done
        states = await asyncio.gather(*(_bounded(ip, p, disc_timeout) for p in disc_list))
        alive = any(state in ("open", "closed") for state in states)
        open_hits = [
            _hit(ip, p) for p, state in zip(disc_list, states) if state == "open" and p in requested
        ]
        if not alive:
            done += 1  # a dead host is fully accounted for after phase 1
            await _emit_progress()
        return ip, alive, open_hits

    async def _sweep(ip: str) -> list[dict]:
        nonlocal done
        hits: list[dict] = []
        if sweep_ports:
            states = await asyncio.gather(*(_bounded(ip, p, timeout) for p in sweep_ports))
            hits = [_hit(ip, p) for p, state in zip(sweep_ports, states) if state == "open"]
        done += 1  # a live host is fully accounted for after phase 2
        await _emit_progress()
        return hits

    for index, chunk in enumerate(chunks):
        if budget_seconds is not None and time.monotonic() - started > budget_seconds:
            logger.warning(
                "Scan budget of %.0fs exceeded after %d/%d chunks of %s; returning partial results.",
                budget_seconds,
                index,
                len(chunks),
                cidr,
            )
            break
        hosts = _chunk_hosts(chunk)
        # Phase 1: who is alive?
        disc_results = await asyncio.gather(*(_discover(ip) for ip in hosts))
        chunk_hits = [hit for _, _, open_hits in disc_results for hit in open_hits]
        live = [ip for ip, alive, _ in disc_results if alive]
        # Phase 2: full port sweep on the live hosts only.
        if live:
            for host_hits in await asyncio.gather(*(_sweep(ip) for ip in live)):
                chunk_hits.extend(host_hits)
        if chunk_hits:
            discovered.extend(chunk_hits)
            if on_hosts is not None:
                await on_hosts(sorted(chunk_hits, key=lambda d: (d["ip"], d["port"])))

    if on_progress is not None and last_pct < 100:
        await on_progress(100)  # a fully-consumed (or budget-truncated) scan always ends at 100
    discovered.sort(key=lambda d: (d["ip"], d["port"]))
    return discovered
