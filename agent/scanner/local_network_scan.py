"""Two-stage local network scan: masscan port discovery + raw HTTP probe.

Runs entirely on the customer LAN — no WireGuard tunnel traversal. Replaces
the old Ares-side per-probe proxy path that funneled every probe through
tunnel-gateway and saturated a single WG tunnel on /16 ranges.

Stage 1 — port discovery:
  * Prefer ``masscan`` (stateless SYN, ~100k pps even on modest hardware).
    Needs ``CAP_NET_RAW`` (the agent container has it). Rate-limited per
    the task's ``rate_pps`` so we don't saturate the customer LAN.
  * Fall back to an asyncio TCP-connect pool when ``masscan`` is absent
    or the kernel rejects raw sockets. Slower but functional.

Stage 2 — HTTP fingerprint on each live ``ip:port``:
  * One GET with 5s timeout, accepting any cert. Capture status + a small
    filtered header set + a body preview + TLS SAN list. No classification
    happens here — Ares-side ``ReconAIAgent`` classifies on raw evidence
    so the pipeline generalizes to unknown targets.

The agent is intentionally a "dumb but fast" probe machine. All semantic
reasoning ("is this an API?", "is this a GraphQL endpoint?") lives in the
LLM on the Ares side.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Optional

import httpx

from agent.scanner.schemas import (
    ALLOWED_PROBE_HEADERS,
    LocalScanDiscovery,
    LocalScanDiscoveryHttp,
    LocalScanTaskConfig,
    LocalScanTaskResult,
    MAX_DISCOVERIES_PER_CHUNK,
    TOOL_MASSCAN,
    TOOL_TCP_CONNECT,
)

logger = logging.getLogger(__name__)

_HTTP_PROBE_TIMEOUT = 5.0
_HTTP_PROBE_CONCURRENCY = 100
_TCP_CONNECT_TIMEOUT = 2.0
_TCP_CONNECT_CONCURRENCY = 500
# Ports where HTTPS is far more likely than HTTP. The probe tries the
# likely scheme first and falls back on failure.
_HTTPS_LIKELY_PORTS = frozenset({443, 8443, 9443, 4443, 7443, 6443})


async def run_local_network_scan(
    cidr: str,
    config: LocalScanTaskConfig,
) -> LocalScanTaskResult:
    """Execute a single /24-or-smaller scan and return the result payload.

    Caller (task_poller) is responsible for POSTing the result back to
    hunt-agent-manager. Raises only on truly unrecoverable conditions —
    timeouts, masscan failures, and per-probe errors are captured into
    ``LocalScanTaskResult.errors`` so the chunk completes cleanly.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []

    # Stage 1: port discovery.
    live_pairs, tool_used = await _discover_open_ports(cidr=cidr, config=config, errors=errors)

    # Cap the result list size before doing any HTTP work — a misconfigured
    # rate_pps against a wide-open subnet could otherwise produce a JSONB
    # row too large to store. Truncate upfront and tell the caller.
    if len(live_pairs) > MAX_DISCOVERIES_PER_CHUNK:
        logger.warning(
            "Discoveries truncated for %s: %d > %d",
            cidr, len(live_pairs), MAX_DISCOVERIES_PER_CHUNK,
        )
        errors.append("discoveries_truncated")
        live_pairs = live_pairs[:MAX_DISCOVERIES_PER_CHUNK]

    # Stage 2: HTTP fingerprint each live ip:port.
    discoveries = await _http_fingerprint(
        live_pairs=live_pairs,
        body_preview_bytes=config.body_preview_bytes,
    )

    completed_at = datetime.now(timezone.utc).isoformat()

    return LocalScanTaskResult(
        cidr_chunk=cidr,
        ports_scanned=list(config.ports),
        scan_started_at=started_at,
        scan_completed_at=completed_at,
        tool_used=tool_used,
        rate_pps_used=config.rate_pps,
        discoveries=discoveries,
        errors=errors,
    )


# ----------------------------------------------------------------------------
# Stage 1: port discovery
# ----------------------------------------------------------------------------


async def _discover_open_ports(
    *,
    cidr: str,
    config: LocalScanTaskConfig,
    errors: list[str],
) -> tuple[list[tuple[str, int]], str]:
    """Returns (live_pairs, tool_name)."""

    if shutil.which("masscan"):
        try:
            pairs = await _masscan_scan(
                cidr=cidr,
                ports=config.ports,
                rate_pps=config.rate_pps,
                wall_clock_budget=config.per_chunk_timeout_seconds,
            )
            return pairs, TOOL_MASSCAN
        except Exception as exc:
            logger.warning(
                "masscan failed for %s (%s); falling back to TCP-connect", cidr, exc,
            )
            errors.append(f"masscan_failed:{exc.__class__.__name__}")

    pairs = await _tcp_connect_scan(
        cidr=cidr,
        ports=config.ports,
        wall_clock_budget=config.per_chunk_timeout_seconds,
        errors=errors,
    )
    return pairs, TOOL_TCP_CONNECT


async def _masscan_scan(
    *,
    cidr: str,
    ports: list[int],
    rate_pps: int,
    wall_clock_budget: int,
) -> list[tuple[str, int]]:
    """Shell out to masscan and parse its JSON output.

    masscan's JSON streams an array; we collect to stdout then parse since
    a /24 result set is bounded (256 hosts × ports). For larger ranges the
    caller should chunk before invoking us.
    """
    port_arg = ",".join(str(p) for p in ports)
    cmd = [
        "masscan",
        cidr,
        "-p", port_arg,
        "--rate", str(rate_pps),
        "-oJ", "-",
        "--wait", "0.5",  # seconds to wait after sending probes for late replies
    ]
    logger.info("masscan: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=wall_clock_budget,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"masscan exceeded {wall_clock_budget}s")

    if proc.returncode not in (0, None):
        stderr_text = (stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"masscan exit={proc.returncode}: {stderr_text[:400]}")

    return _parse_masscan_json(stdout)


def _parse_masscan_json(raw: bytes) -> list[tuple[str, int]]:
    """Tolerate masscan's quirky JSON output.

    Newer masscan emits a top-level JSON array; older builds emit
    line-delimited objects separated by commas. Strip trailing commas and
    try array-parse first; fall back to line-by-line.
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    pairs: list[tuple[str, int]] = []

    # Try array parse first.
    try:
        # masscan likes to leave a trailing comma before EOF; tolerate.
        candidate = text.rstrip().rstrip(",")
        if not candidate.startswith("["):
            candidate = "[" + candidate + "]"
        entries = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        entries = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                entries.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue

    seen: set[tuple[str, int]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip")
        ports = entry.get("ports") or []
        for p in ports:
            if p.get("status") != "open":
                continue
            try:
                port = int(p.get("port"))
            except (TypeError, ValueError):
                continue
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)

    return pairs


async def _tcp_connect_scan(
    *,
    cidr: str,
    ports: list[int],
    wall_clock_budget: int,
    errors: list[str],
) -> list[tuple[str, int]]:
    """Fallback when masscan isn't available — bounded asyncio TCP connects."""
    import ipaddress

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        errors.append(f"invalid_cidr:{exc}")
        return []

    hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
    targets: list[tuple[str, int]] = [(str(ip), port) for ip in hosts for port in ports]

    sem = asyncio.Semaphore(_TCP_CONNECT_CONCURRENCY)
    live: list[tuple[str, int]] = []

    async def probe(ip: str, port: int) -> None:
        async with sem:
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=_TCP_CONNECT_TIMEOUT)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                live.append((ip, port))
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return

    try:
        await asyncio.wait_for(
            asyncio.gather(*[probe(ip, port) for (ip, port) in targets]),
            timeout=wall_clock_budget,
        )
    except asyncio.TimeoutError:
        errors.append("tcp_connect_total_timeout")

    return live


# ----------------------------------------------------------------------------
# Stage 2: HTTP fingerprint
# ----------------------------------------------------------------------------


async def _http_fingerprint(
    *,
    live_pairs: list[tuple[str, int]],
    body_preview_bytes: int,
) -> list[LocalScanDiscovery]:
    """Issue one GET per live ip:port, capture status + filtered headers
    + small body preview + TLS SAN. No classification."""
    if not live_pairs:
        return []

    sem = asyncio.Semaphore(_HTTP_PROBE_CONCURRENCY)

    async def probe_one(ip: str, port: int) -> LocalScanDiscovery:
        async with sem:
            http = await _http_probe_single(ip, port, body_preview_bytes)
            return LocalScanDiscovery(ip=ip, port=port, alive=True, http=http)

    return await asyncio.gather(*[probe_one(ip, port) for (ip, port) in live_pairs])


async def _http_probe_single(
    ip: str, port: int, body_preview_bytes: int,
) -> Optional[LocalScanDiscoveryHttp]:
    """Try HTTPS first for known TLS ports, HTTP otherwise; fall back on failure."""
    schemes = (
        ("https", "http") if port in _HTTPS_LIKELY_PORTS else ("http", "https")
    )

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=_HTTP_PROBE_TIMEOUT, follow_redirects=False,
            ) as client:
                response = await client.get(url)
        except (httpx.RequestError, ssl.SSLError, OSError):
            continue

        body_bytes = response.content[:body_preview_bytes] if response.content else b""
        headers = {
            k.lower(): v
            for k, v in response.headers.items()
            if k.lower() in ALLOWED_PROBE_HEADERS
        }
        san = await _tls_sans(ip, port) if scheme == "https" else None
        return LocalScanDiscoveryHttp(
            status=response.status_code,
            headers=headers,
            body_preview_b64=base64.b64encode(bytes(body_bytes)).decode("ascii"),
            tls_cert_san=san,
        )

    return None


async def _tls_sans(ip: str, port: int) -> Optional[list[str]]:
    """Best-effort TLS handshake to pull the cert's SAN list.

    The cert's SANs are the most generalizable per-service fingerprint a
    scanner gets without parsing the body — useful evidence for the
    downstream LLM classifier. Failures are not fatal; we return None.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _grab() -> Optional[list[str]]:
        try:
            with socket.create_connection((ip, port), timeout=_HTTP_PROBE_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                    cert = tls.getpeercert()
            if not cert:
                return None
            sans: list[str] = []
            for kind, value in cert.get("subjectAltName", ()):
                if kind == "DNS":
                    sans.append(value)
            return sans or None
        except (OSError, ssl.SSLError):
            return None

    return await asyncio.get_running_loop().run_in_executor(None, _grab)
