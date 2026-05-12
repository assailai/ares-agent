"""Polls hunt-agent-manager for tasks and dispatches them.

Today the only task type the agent handles is ``local_network_scan``;
adding more is a switch on ``task_type`` inside ``_handle_task``.

Auth: bearer JWT issued at registration, stored in ``AgentConfig.JWT_TOKEN``.

This is intentionally simple — one in-flight task at a time, bounded by
the per-chunk timeout in the task's ``tool_config``. Concurrency at the
agent level isn't useful since masscan saturates the link anyway.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx
from pydantic import ValidationError

from agent.database.models import AgentConfig, get_config
from agent.scanner.local_network_scan import run_local_network_scan
from agent.scanner.schemas import (
    LocalScanTaskConfig,
    TASK_TYPE_LOCAL_NETWORK_SCAN,
)

logger = logging.getLogger(__name__)

_POLL_INTERVAL_IDLE = 30  # seconds between polls when no tasks
_POLL_INTERVAL_BUSY = 1   # seconds before checking for the next task
_HTTP_CLIENT_TIMEOUT = 30.0


async def poll_loop() -> None:
    """Background coroutine — entry point from main.py lifespan."""
    logger.info("📋 Task-polling loop started")
    while True:
        try:
            if not _agent_ready():
                await asyncio.sleep(_POLL_INTERVAL_IDLE)
                continue

            picked_task = await _poll_and_dispatch_once()

            # If we just handled a task, check again quickly — there may be more.
            await asyncio.sleep(_POLL_INTERVAL_BUSY if picked_task else _POLL_INTERVAL_IDLE)

        except asyncio.CancelledError:
            logger.info("Task-polling loop stopped")
            raise
        except Exception as exc:
            logger.error("Task poll loop error: %s", exc, exc_info=True)
            await asyncio.sleep(_POLL_INTERVAL_IDLE)


def _agent_ready() -> bool:
    return bool(get_config(AgentConfig.PLATFORM_URL)) and bool(get_config(AgentConfig.JWT_TOKEN))


def _platform_base() -> str:
    return (get_config(AgentConfig.PLATFORM_URL) or "").rstrip("/")


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {get_config(AgentConfig.JWT_TOKEN)}"}


async def _poll_and_dispatch_once() -> bool:
    """Pull at most one task off the queue and execute it. Returns True if
    a task was picked up (so the caller can short-poll for the next)."""
    tasks = await _fetch_pending_tasks()
    if not tasks:
        return False

    task = tasks[0]
    task_id = task.get("id")
    task_type = task.get("task_type")
    if not task_id or not task_type:
        logger.warning("Skipping malformed task: %s", task)
        return False

    await _handle_task(task)
    return True


async def _fetch_pending_tasks() -> list[dict]:
    url = f"{_platform_base()}/api/v1/agent/tasks"
    try:
        async with httpx.AsyncClient(verify=True, timeout=_HTTP_CLIENT_TIMEOUT) as client:
            response = await client.get(url, headers=_auth_headers())
    except httpx.RequestError as exc:
        logger.debug("Task poll request failed: %s", exc)
        return []

    if response.status_code == 401:
        logger.warning("Task poll: auth token invalid or expired")
        return []
    if response.status_code != 200:
        logger.debug("Task poll: HTTP %s", response.status_code)
        return []

    try:
        payload = response.json()
    except ValueError:
        logger.warning("Task poll: non-JSON response")
        return []

    return payload.get("tasks", []) or []


async def _handle_task(task: dict) -> None:
    task_id = task["id"]
    task_type = task["task_type"]

    await _mark_started(task_id)

    try:
        if task_type == TASK_TYPE_LOCAL_NETWORK_SCAN:
            await _run_local_network_scan_task(task)
        else:
            logger.warning("Unknown task_type %r — failing", task_type)
            await _mark_failed(task_id, f"unsupported task_type: {task_type}")
    except Exception as exc:
        logger.error("Task %s handler raised: %s", task_id, exc, exc_info=True)
        await _mark_failed(task_id, f"{exc.__class__.__name__}: {exc}")


async def _run_local_network_scan_task(task: dict) -> None:
    task_id = task["id"]
    cidr = task.get("target_network")
    raw_config = task.get("tool_config") or {}

    if not cidr:
        await _mark_failed(task_id, "missing target_network")
        return

    try:
        config = LocalScanTaskConfig.model_validate(raw_config)
    except ValidationError as exc:
        await _mark_failed(task_id, f"invalid tool_config: {exc}")
        return

    logger.info("🔍 Running local_network_scan: %s ports=%s rate=%d",
                cidr, config.ports, config.rate_pps)

    result = await run_local_network_scan(cidr=cidr, config=config)
    await _mark_complete(task_id, result.model_dump())

    logger.info(
        "✅ Completed local_network_scan %s: %d discoveries via %s (errors=%s)",
        task_id, len(result.discoveries), result.tool_used, result.errors,
    )


# ----------------------------------------------------------------------------
# Lifecycle hooks against hunt-agent-manager
# ----------------------------------------------------------------------------


async def _mark_started(task_id: str) -> None:
    await _post_lifecycle(f"/api/v1/agent/tasks/{task_id}/start", json_body={})


async def _mark_complete(task_id: str, result_payload: dict) -> None:
    await _post_lifecycle(f"/api/v1/agent/tasks/{task_id}/complete", json_body=result_payload)


async def _mark_failed(task_id: str, error_message: str) -> None:
    await _post_lifecycle(
        f"/api/v1/agent/tasks/{task_id}/fail",
        json_body={"error_message": error_message},
    )


async def _post_lifecycle(path: str, *, json_body: dict) -> None:
    url = f"{_platform_base()}{path}"
    try:
        async with httpx.AsyncClient(verify=True, timeout=_HTTP_CLIENT_TIMEOUT) as client:
            response = await client.post(url, headers=_auth_headers(), json=json_body)
        if response.status_code >= 400:
            logger.warning("Lifecycle POST %s -> %s: %s", path, response.status_code, response.text[:200])
    except httpx.RequestError as exc:
        logger.warning("Lifecycle POST %s failed: %s", path, exc)
