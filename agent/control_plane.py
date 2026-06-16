"""HTTPS control-plane client: every call the agent makes to ares-v2.

Outbound only. The agent registers once with a one-time token (receiving a long-lived
bearer token), then heartbeats, polls for tasks, and reports results. TLS is verified
unless ``ARES_INSECURE`` is set (local dev against plain http / self-signed).
"""

from __future__ import annotations

import os
import platform
import socket

import httpx

from agent.config import Settings


class RegistrationRejected(Exception):
    """The registration token was rejected (expired, already used, or unknown)."""


def system_info() -> dict:
    arch_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    arch = arch_map.get(platform.machine().lower(), platform.machine().lower())
    try:
        with open("/proc/meminfo") as f:
            memory_mb = int(f.readline().split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        memory_mb = None
    return {
        "os": platform.system().lower(),
        "arch": arch,
        "cpu_cores": os.cpu_count(),
        "memory_mb": memory_mb,
    }


def _client(settings: Settings) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.base_url, timeout=30.0, verify=not settings.insecure
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def register(settings: Settings, *, networks: list[str], name: str) -> dict:
    body = {
        "registration_token": settings.token,
        "internal_networks": networks,
        "name": name or None,
        "hostname": socket.gethostname(),
        "agent_version": settings.agent_version,
        "capabilities": ["local_network_scan"],
        "system_info": system_info(),
    }
    async with _client(settings) as client:
        resp = await client.post("/api/v1/agent/register", json=body)
    if resp.status_code == 401:
        raise RegistrationRejected(resp.text[:200])
    resp.raise_for_status()
    return resp.json()


async def heartbeat(
    settings: Settings,
    token: str,
    *,
    public_ip: str | None = None,
    last_handshake_at: str | None = None,
) -> dict:
    body: dict[str, object] = {"agent_version": settings.agent_version}
    if public_ip is not None:
        body["public_ip"] = public_ip
    if last_handshake_at is not None:
        body["last_handshake_at"] = last_handshake_at
    async with _client(settings) as client:
        resp = await client.post("/api/v1/agent/heartbeat", json=body, headers=_auth(token))
    resp.raise_for_status()
    return resp.json()


async def poll_tasks(settings: Settings, token: str) -> list[dict]:
    async with _client(settings) as client:
        resp = await client.get("/api/v1/agent/tasks", headers=_auth(token))
    resp.raise_for_status()
    return resp.json().get("tasks", []) or []


async def task_started(settings: Settings, token: str, task_id: str) -> None:
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/start", json={}, headers=_auth(token)
        )
    resp.raise_for_status()


async def task_completed(
    settings: Settings, token: str, task_id: str, discovered_hosts: list[dict]
) -> None:
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/complete",
            json={"discovered_hosts": discovered_hosts},
            headers=_auth(token),
        )
    resp.raise_for_status()


async def task_failed(settings: Settings, token: str, task_id: str, reason: str) -> None:
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/fail",
            json={"failure_reason": reason},
            headers=_auth(token),
        )
    resp.raise_for_status()
