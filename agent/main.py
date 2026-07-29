"""Ares Docker Agent: headless, zero-touch control-plane client.

One command runs it: ``docker run -e ARES_TOKEN=... assailai/ares-agent``. The agent
auto-detects its internal LAN(s), registers over HTTPS, then heartbeats and polls for scan
tasks. When an internal hunt is running it opens an outbound data-plane tunnel so ares can
reach the discovered internal hosts. There is no web UI and no interactive setup; logs
narrate each step so an operator can self-diagnose.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import resource
import sys
import time
from urllib.parse import urlparse

import httpx

from agent import control_plane, netdetect, scan
from agent.config import settings
from agent.health.system_metrics import read_cpu_percent, read_memory_percent
from agent.state import AgentState, load_state, save_state
from agent.tunnel import TunnelManager, tunnel_url

logger = logging.getLogger("ares.agent")


class _AuthInvalidated(Exception):
    """The control plane rejected our agent token past the retry threshold.

    Raised out of the heartbeat loop so :func:`run` can drop the stale identity and
    re-enroll with ARES_TOKEN, rather than 401-looping forever on dead credentials.
    """

# scan concurrency resolved at startup against the file-descriptor budget (see
# _resolve_scan_limits); per-connect timeouts + range breadth come from settings.
_scan_limits = {"concurrency": 512}
# file-descriptor target so high scan concurrency has enough sockets (headroom left for the
# control-plane client and the data-plane tunnel).
_FD_TARGET = 65536
_FD_RESERVE = 256
# floor so a tiny fd budget still leaves the scanner usable.
_MIN_CONCURRENCY = 64
_REGISTER_RETRY_SECONDS = 10
# Consecutive 401s on the heartbeat before we attempt to re-enroll. A single 401 can be a
# momentary blip (a load balancer mid-rollover); a streak means the stored agent token was
# rejected for real (stale kept-volume creds or a decommissioned agent). The re-enroll it
# triggers is non-destructive (see _reenroll), so the streak only needs to filter blips, not
# to prove a decommission: a transient 401 on a healthy agent recovers on its own.
_REENROLL_AFTER_UNAUTHORIZED = 3
# How long to wait before serving again after a re-enroll attempt failed (the registration
# token is spent, or Ares was unreachable). Paces the retry so a decommissioned agent idles
# quietly instead of busy-looping, without ever exiting the process (which would hand the
# restart cadence to Docker and risk a fast restart storm).
_REENROLL_RETRY_SECONDS = 60
# hosts for which a plaintext / unverified ARES_URL is acceptable (local + staging only).
_INSECURE_OK_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal")
# cadence the server hands back at register / heartbeat (sane defaults until then).
_cadence = {"heartbeat": 30, "poll": 5}
# captured at import (process start) so heartbeats can report uptime since connect.
_AGENT_START_MONOTONIC = time.monotonic()
# monotonic times of the last successful control-plane contact (heartbeat or task poll) and the
# last healthcheck-marker write. The watchdog compares last_contact to decide the agent has gone
# dark; last_marker_at throttles the marker file so it does not churn /data on every poll.
_liveness = {"last_contact": time.monotonic(), "last_marker_at": 0.0}
# how often the watchdog checks liveness (well below max_offline_seconds, so the exit is timely).
_WATCHDOG_INTERVAL_SECONDS = 30
# rewrite the healthcheck marker at most this often: the watchdog uses the in-memory clock, so the
# file only needs to stay fresh enough for the probe's max_offline_seconds grace window.
_MARKER_MIN_INTERVAL_SECONDS = 30
# bound on the threadpool-dispatched CPU sample: a pool starved by hung DNS lookups must never
# wedge the heartbeat, so the sample is skipped past this timeout.
_CPU_SAMPLE_TIMEOUT_SECONDS = 5


def _configure_logging() -> None:
    """Configure logging so ``ARES_LOG_LEVEL`` only ever raises the verbosity of *our* loggers.

    The level is deliberately NOT handed to ``basicConfig``: that sets the **root** level, which
    would turn on DEBUG for every dependency too. ``websockets`` logs each frame it sends and
    receives at DEBUG (``protocol.py``: ``logger.debug("< %s", frame)``), and a frame's repr renders
    the payload as hex - which for the data-plane tunnel is the customer's own relayed traffic, in
    plaintext whenever the target speaks http. An operator raising the log level to debug their
    agent must never start dumping that.

    Root stays at INFO so third-party DEBUG records are dropped at their own logger; ``ares.*`` gets
    the configured level. This works because the root *handler* is left at NOTSET, so a DEBUG record
    admitted by ``ares.agent`` still reaches it.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("ares").setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


def _resolve_scan_limits() -> None:
    """Raise the file-descriptor soft limit so high scan concurrency has enough sockets, then clamp
    the effective concurrency to what that budget allows (reserving headroom for the control-plane
    client and the tunnel). Degrades gracefully: if the limit cannot be raised, concurrency simply
    tracks whatever the current budget is."""
    soft = 1024
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = _FD_TARGET if hard == resource.RLIM_INFINITY else min(_FD_TARGET, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
    except (OSError, ValueError) as exc:
        logger.debug("could not raise file-descriptor limit: %s", exc)
    concurrency = max(_MIN_CONCURRENCY, min(settings.scan_concurrency, soft - _FD_RESERVE))
    _scan_limits["concurrency"] = concurrency
    logger.info("Scan concurrency=%d (file-descriptor soft limit=%d)", concurrency, soft)


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


def _allowed_hosts(value: object) -> list[str]:
    """The hostname destinations ares named on this heartbeat, ignoring anything malformed.

    A bad field must never cost us the tunnel, and it must never *widen* the allowlist either:
    anything that is not a list of strings degrades to "no pushed hosts", which leaves the
    registered-network rule as the only way in."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _write_update_target(version: str) -> None:
    """Record the version the companion updater should move this agent to.

    The updater is a separate, privileged container that reads this from the shared data
    dir and applies it (recreate / rolling update); the agent itself never touches the
    container runtime. Best-effort: if the shared dir is not mounted (no updater deployed),
    log at debug and carry on."""
    path = settings.update_target_path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": version}))
        tmp.replace(path)
    except OSError as exc:
        logger.debug("could not write update target (%s); is the shared volume mounted?", exc)


def _record_contact() -> None:
    """Mark a successful control-plane contact: bump the watchdog's liveness clock (every call) and
    refresh the healthcheck marker file (throttled). The in-memory clock is what the watchdog reads;
    the marker only backs the container HEALTHCHECK / k8s liveness probe, so it is rewritten at most
    every _MARKER_MIN_INTERVAL_SECONDS to avoid churning /data on the ~5s poll cadence. Best-effort
    on the file."""
    now = time.monotonic()
    _liveness["last_contact"] = now
    if now - _liveness["last_marker_at"] < _MARKER_MIN_INTERVAL_SECONDS:
        return
    _liveness["last_marker_at"] = now
    try:
        marker = settings.data_dir / "last-contact"
        tmp = marker.with_suffix(".tmp")
        tmp.write_text(str(int(time.time())))
        tmp.replace(marker)
    except OSError as exc:
        logger.debug("could not write liveness marker: %s", exc)


async def _sample_cpu_percent() -> float | None:
    """Read CPU% off the loop's default thread pool, bounded by a timeout. The metric is
    best-effort: a slow or starved pool (e.g. leaked, non-cancellable getaddrinfo threads during a
    DNS outage) must never wedge the heartbeat here, so on timeout/error we skip it and let the beat
    proceed (reporting no CPU) rather than block forever."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(read_cpu_percent), _CPU_SAMPLE_TIMEOUT_SECONDS
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - metric is best-effort; never block or fail the beat
        logger.debug("cpu sample skipped: %s", exc)
        return None


async def _watchdog_loop() -> None:
    """Exit the process when the agent has had no successful contact with Ares for
    ``max_offline_seconds``, so the container runtime restarts it fresh (a new process re-resolves
    DNS and rebuilds its client / thread pool). This is the recovery of last resort for a wedged or
    network-isolated agent that the in-loop retries cannot rescue. It only sleeps and compares
    monotonic time, never touching the network or the shared thread pool, so the same starvation
    that can wedge the heartbeat/poll loops cannot wedge the watchdog too.

    Scope (accepted gap): the watchdog runs only while serving (started in ``_serve``), so initial
    ``_enroll`` and post-401 ``_reenroll`` are not covered. That is deliberate and low risk: those
    loops make network calls through fresh, short-timeout clients that fail-and-retry rather than
    hang, and the thread-pool starvation this guards against only arises in the long-lived serving
    loops - so there is nothing here for a last-resort exit to rescue."""
    while True:
        await asyncio.sleep(_WATCHDOG_INTERVAL_SECONDS)
        offline_for = time.monotonic() - _liveness["last_contact"]
        if offline_for >= settings.max_offline_seconds:
            logger.error(
                "No successful contact with Ares for %.0fs (limit %ds); exiting so the container "
                "restarts and reconnects.",
                offline_for,
                settings.max_offline_seconds,
            )
            os._exit(1)


async def _heartbeat_loop(state: AgentState, tunnel: TunnelManager) -> None:
    failures = 0
    unauthorized = 0
    online_announced = False
    while True:
        try:
            # CPU sampling reads the cgroup counter twice on the first call; keep it off the loop.
            # Bounded so a thread pool starved by hung DNS lookups can never wedge the beat here.
            cpu_percent = await _sample_cpu_percent()
            resp = await control_plane.heartbeat(
                settings,
                state.agent_token or "",
                cpu_percent=cpu_percent,
                memory_percent=read_memory_percent(),
                uptime_seconds=int(time.monotonic() - _AGENT_START_MONOTONIC),
            )
            # Announce "online" only once the control plane has actually accepted a beat, so
            # the log never claims the agent is up while its credentials are in fact rejected.
            if not online_announced:
                logger.info(
                    'Agent online, visible in the dashboard as "%s".',
                    settings.agent_name or "this host",
                )
                online_announced = True
            if failures:
                logger.info("Heartbeat recovered after %d failed attempt(s).", failures)
            failures = 0
            unauthorized = 0
            _record_contact()  # feed the watchdog + refresh the healthcheck marker
            _cadence["heartbeat"] = resp.get("heartbeat_interval_seconds", _cadence["heartbeat"])
            tunnel.sync(
                bool(resp.get("tunnel_required")),
                _allowed_hosts(resp.get("tunnel_allowed_hosts")),
            )
            if resp.get("restart_requested"):
                logger.warning("Restart requested from dashboard; exiting for container restart.")
                os._exit(0)
            if resp.get("update_pending") and resp.get("latest_version"):
                _write_update_target(resp["latest_version"])
        except asyncio.CancelledError:
            raise
        except httpx.HTTPStatusError as exc:
            failures += 1
            if exc.response.status_code == 401:
                unauthorized += 1
                if unauthorized >= _REENROLL_AFTER_UNAUTHORIZED:
                    # Sustained rejection: the stored token is dead. Surface it so run() can
                    # drop the identity and re-enroll instead of 401-looping forever.
                    raise _AuthInvalidated from exc
                logger.warning(
                    "Heartbeat unauthorized (%d/%d): the stored agent credentials look stale or "
                    "the agent was decommissioned; will re-enroll with ARES_TOKEN if this persists.",
                    unauthorized,
                    _REENROLL_AFTER_UNAUTHORIZED,
                )
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
    budget = config.get("timeout_seconds")
    if not cidr:
        await control_plane.task_failed(settings, token, task_id, "missing target_network")
        return
    await control_plane.task_started(settings, token, task_id)

    last_pct = 0

    async def _report(percent: int, hosts: list[dict] | None = None) -> None:
        # best-effort: progress + streamed hosts are a live-UX nicety, never allowed to fail the
        # scan. task_completed sends the authoritative full list, and the server de-dups it.
        try:
            await control_plane.task_progress(
                settings, token, task_id, percent=percent, discovered_hosts=hosts
            )
        except Exception as exc:  # noqa: BLE001 - a dropped progress post is not fatal
            logger.debug("progress report for task %s failed: %s", task_id, exc)

    async def _on_progress(percent: int) -> None:
        nonlocal last_pct
        last_pct = percent
        await _report(percent)

    async def _on_hosts(chunk: list[dict]) -> None:
        await _report(last_pct, chunk)

    try:
        logger.info("Scanning %s across %d port(s)", cidr, len(ports))
        hosts = await scan.scan_cidr(
            cidr,
            ports,
            timeout=settings.scan_connect_timeout,
            discovery_timeout=settings.scan_discovery_timeout,
            concurrency=_scan_limits["concurrency"],
            max_hosts=settings.scan_max_hosts,
            chunk_prefix=settings.scan_chunk_prefix,
            budget_seconds=budget,
            on_progress=_on_progress,
            on_hosts=_on_hosts,
        )
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
            _record_contact()  # a successful poll is also live contact with Ares
            for task in tasks:
                await _run_task(state.agent_token or "", task)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep polling through any transient error
            failures += 1
            _log_repeated_failure("task poll", failures, exc)
        await asyncio.sleep(_cadence["poll"])


async def _enroll(networks: list[str]) -> AgentState | None:
    """Return a registered state, re-using a stored identity or enrolling with ARES_TOKEN.

    Retries transient connectivity errors forever (the control plane may not be reachable
    yet); returns None only when the registration token is rejected outright (expired or
    already used), which is fatal and the caller surfaces to the operator.
    """
    state = load_state(settings.state_path)
    while not state.registered:
        try:
            state = await _register(state, networks)
        except control_plane.RegistrationRejected:
            logger.error(
                "Registration token rejected (expired or already used). "
                "Generate a fresh token in the Ares dashboard."
            )
            return None
        except (httpx.HTTPError, OSError) as exc:
            logger.error(
                "Cannot reach Ares at %s: %s. Retrying in %ds.",
                settings.base_url,
                exc,
                _REGISTER_RETRY_SECONDS,
            )
            await asyncio.sleep(_REGISTER_RETRY_SECONDS)
    return state


async def _reenroll(networks: list[str]) -> AgentState | None:
    """Mint a fresh identity with ARES_TOKEN after the stored credentials were rejected.

    Non-destructive by design: this enrolls into a brand-new state and only persists it on
    success, so the caller can keep the existing credentials if this fails. It succeeds only
    when ARES_TOKEN is still an unused, valid registration token (the kept-volume case, where
    the stored token was minted for a previous container). It returns None when the token is
    already spent (a decommissioned agent, or a healthy agent that merely hit a transient 401)
    or Ares is unreachable, so a blanket 401 never strands the agent on a one-time token.
    """
    try:
        return await _register(AgentState(), networks)
    except control_plane.RegistrationRejected:
        return None
    except (httpx.HTTPError, OSError) as exc:
        logger.debug("re-enrollment could not reach Ares: %s", exc)
        return None


async def _serve(state: AgentState, tunnel: TunnelManager) -> None:
    """Run the heartbeat and task-poll loops until one exits. If either raises (e.g. the
    heartbeat raises _AuthInvalidated on a sustained 401), cancel its sibling and re-raise
    so the caller decides whether to re-enroll or shut down.

    A watchdog task runs alongside the loops: if the agent has no successful contact with Ares for
    ``max_offline_seconds`` it exits the process so the container restarts fresh. Reset the liveness
    clock here so each serving session (including one entered after a re-enroll) starts with a full
    grace window rather than inheriting a stale timestamp."""
    _liveness["last_contact"] = time.monotonic()
    tasks = {
        asyncio.create_task(_heartbeat_loop(state, tunnel)),
        asyncio.create_task(_poll_loop(state)),
        asyncio.create_task(_watchdog_loop()),
    }
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        exc = task.exception()
        if exc is not None:
            raise exc


async def run() -> int:
    _configure_logging()
    if not settings.token.get_secret_value():
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
    _resolve_scan_limits()
    networks = settings.network_overrides() or netdetect.scan_targets(settings.scan_scope)
    if not networks:
        logger.warning(
            "No internal LAN auto-detected and ARES_NETWORKS is unset; registering with no "
            "networks. Set ARES_NETWORKS=10.0.0.0/24,... or edit them in the dashboard."
        )
    else:
        logger.info("Scanning networks (scope=%s): %s", settings.scan_scope, ", ".join(networks))

    state = await _enroll(networks)
    if state is None:
        return 1

    # Serve forever, self-healing across credential rejections. A sustained 401 means the
    # stored token was rejected (stale kept-volume creds, or a decommissioned agent); we try
    # to re-enroll with ARES_TOKEN but never discard the current credentials first, and never
    # exit the process over it. Re-enrollment replaces the identity only on success (a fresh,
    # unused token), so a transient 401 on a healthy agent recovers on its own and a spent
    # token leaves the agent intact rather than crash-looping.
    while True:
        tunnel = TunnelManager(
            tunnel_url(settings.base_url),
            state.agent_token or "",
            networks,
            insecure=settings.insecure,
        )
        try:
            await _serve(state, tunnel)
        except _AuthInvalidated:
            logger.warning(
                "Control plane rejected the stored agent credentials; attempting to "
                "re-enroll with ARES_TOKEN."
            )
            reenrolled = await _reenroll(networks)
            if reenrolled is not None:
                state = reenrolled
                logger.info("Re-enrolled with a fresh agent identity.")
            else:
                logger.error(
                    "Could not re-enroll: the registration token is spent or Ares is "
                    "unreachable. Keeping the current credentials and retrying. If this agent "
                    "was decommissioned, stop the container; to give it a new identity, "
                    "redeploy with a fresh ARES_TOKEN."
                )
                await asyncio.sleep(_REENROLL_RETRY_SECONDS)
        else:
            return 0  # both loops ended without error: nothing left to do
        finally:
            tunnel.stop()


def main() -> None:
    try:
        raise SystemExit(asyncio.run(run()))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
