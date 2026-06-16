"""Ares Docker Agent: headless, zero-touch control-plane client.

One command runs it: ``docker run -e ARES_TOKEN=... ghcr.io/assailai/ares-agent``. The agent
auto-detects its internal LAN(s), registers over HTTPS, then heartbeats and polls for scan
tasks. When an internal hunt is running it opens an outbound data-plane tunnel so ares can
reach the discovered internal hosts. There is no web UI and no interactive setup; logs
narrate each step so an operator can self-diagnose.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from urllib.parse import urlparse

import httpx

from agent import control_plane, netdetect, scan
from agent.config import settings
from agent.state import AgentState, load_state, save_state
from agent.tunnel import TunnelManager, tunnel_url

logger = logging.getLogger("ares.agent")

# per-connect probe timeout (the task's timeout_seconds is the whole-chunk budget).
_PROBE_TIMEOUT = 2.0
_REGISTER_RETRY_SECONDS = 10
# hosts for which a plaintext / unverified ARES_URL is acceptable (local + staging only).
_INSECURE_OK_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal")
# cadence the server hands back at register / heartbeat (sane defaults until then).
_cadence = {"heartbeat": 30, "poll": 5}


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _insecure_allowed(base_url: str) -> bool:
    """ARES_INSECURE skips TLS verification, so only allow it against local / staging."""
    host = urlparse(base_url).hostname or ""
    return host in _INSECURE_OK_HOSTS or host.endswith(".local") or "staging" in host


async def _register(state: AgentState, networks: list[str]) -> AgentState:
    logger.info("Registering with %s (networks=%s)", settings.base_url, networks or "none")
    resp = await control_plane.register(settings, networks=networks, name=settings.agent_name)
    state.agent_id = resp["agent_id"]
    state.agent_token = resp["agent_token"]
    _cadence["heartbeat"] = resp.get("heartbeat_interval_seconds", _cadence["heartbeat"])
    _cadence["poll"] = resp.get("poll_interval_seconds", _cadence["poll"])
    save_state(settings.state_path, state)
    logger.info("Registered as agent %s", state.agent_id)
    return state


def _log_repeated_failure(what: str, failures: int, exc: Exception) -> None:
    """Surface sustained trouble without spamming the log: the first failure and every
    tenth after it are WARNING (visible at the default INFO level); the rest stay DEBUG.
    The caller logs the matching recovery once the call succeeds again."""
    if failures == 1 or failures % 10 == 0:
        logger.warning("%s failing (attempt %d): %s", what, failures, exc)
    else:
        logger.debug("%s failed (attempt %d): %s", what, failures, exc)


async def _heartbeat_loop(state: AgentState, tunnel: TunnelManager) -> None:
    failures = 0
    while True:
        try:
            resp = await control_plane.heartbeat(settings, state.agent_token or "")
            if failures:
                logger.info("Heartbeat recovered after %d failed attempt(s).", failures)
                failures = 0
            _cadence["heartbeat"] = resp.get("heartbeat_interval_seconds", _cadence["heartbeat"])
            tunnel.sync(bool(resp.get("tunnel_required")))
            if resp.get("restart_requested"):
                logger.warning("Restart requested from dashboard; exiting for container restart.")
                os._exit(0)
            if resp.get("update_pending"):
                logger.info(
                    "Update queued (latest=%s); self-update is not wired in this build.",
                    resp.get("latest_version"),
                )
        except asyncio.CancelledError:
            raise
        except httpx.HTTPStatusError as exc:
            failures += 1
            if exc.response.status_code == 401:
                logger.error("Heartbeat unauthorized: the agent may have been decommissioned.")
            else:
                _log_repeated_failure("heartbeat", failures, exc)
        except Exception as exc:  # noqa: BLE001 - keep heartbeating through any transient error
            failures += 1
            _log_repeated_failure("heartbeat", failures, exc)
        await asyncio.sleep(_cadence["heartbeat"])


async def _run_task(token: str, task: dict) -> None:
    task_id = task["id"]
    cidr = task.get("target_network")
    config = task.get("tool_config") or {}
    ports = config.get("ports") or list(scan.DEFAULT_PORTS)
    if not cidr:
        await control_plane.task_failed(settings, token, task_id, "missing target_network")
        return
    await control_plane.task_started(settings, token, task_id)
    try:
        logger.info("Scanning %s on ports %s", cidr, ports)
        hosts = await scan.scan_cidr(cidr, ports, timeout=_PROBE_TIMEOUT)
        await control_plane.task_completed(settings, token, task_id, hosts)
        logger.info("Reported %d discovered host(s) for %s", len(hosts), cidr)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - report any scan failure instead of dropping the task
        logger.error("Scan task %s failed: %s", task_id, exc)
        await control_plane.task_failed(settings, token, task_id, f"{type(exc).__name__}: {exc}")


async def _poll_loop(state: AgentState) -> None:
    failures = 0
    while True:
        try:
            tasks = await control_plane.poll_tasks(settings, state.agent_token or "")
            if failures:
                logger.info("Task polling recovered after %d failed attempt(s).", failures)
                failures = 0
            for task in tasks:
                await _run_task(state.agent_token or "", task)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep polling through any transient error
            failures += 1
            _log_repeated_failure("task poll", failures, exc)
        await asyncio.sleep(_cadence["poll"])


async def run() -> int:
    _configure_logging()
    if not settings.token:
        logger.error(
            "ARES_TOKEN is required. Generate a registration token in the Ares dashboard "
            "(Settings -> Agents) and pass it as -e ARES_TOKEN=..."
        )
        return 1
    if settings.insecure and not _insecure_allowed(settings.base_url):
        logger.error(
            "ARES_INSECURE=true skips TLS verification and is only allowed for local / staging "
            "URLs, not %s. Refusing to start.",
            settings.base_url,
        )
        return 1

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    state = load_state(settings.state_path)
    networks = settings.network_overrides() or netdetect.detect_networks()
    if not networks:
        logger.warning(
            "No internal LAN auto-detected and ARES_NETWORKS is unset; registering with no "
            "networks. Set ARES_NETWORKS=10.0.0.0/24,... or edit them in the dashboard."
        )

    while not state.registered:
        try:
            state = await _register(state, networks)
        except control_plane.RegistrationRejected:
            logger.error(
                "Registration token rejected (expired or already used). "
                "Generate a fresh token in the Ares dashboard."
            )
            return 1
        except (httpx.HTTPError, OSError) as exc:
            logger.error(
                "Cannot reach Ares at %s: %s. Retrying in %ds.",
                settings.base_url,
                exc,
                _REGISTER_RETRY_SECONDS,
            )
            await asyncio.sleep(_REGISTER_RETRY_SECONDS)

    tunnel = TunnelManager(
        tunnel_url(settings.base_url),
        state.agent_token or "",
        networks,
        insecure=settings.insecure,
    )
    logger.info('Agent online, visible in the dashboard as "%s".', settings.agent_name or "this host")
    try:
        await asyncio.gather(_heartbeat_loop(state, tunnel), _poll_loop(state))
    finally:
        tunnel.stop()
    return 0


def main() -> None:
    try:
        raise SystemExit(asyncio.run(run()))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
