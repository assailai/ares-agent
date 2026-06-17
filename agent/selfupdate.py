"""Optional dashboard-driven self-update (requires the Docker socket).

When the dashboard marks a target version and queues an upgrade, and ``ARES_SELF_UPDATE``
is on, the agent launches a short-lived updater container (its own image, running
``agent.updater``) that recreates this container on the pinned target tag. The swap is
fail-safe: the replacement is verified up before the old container is removed, so a bad
version never takes the agent down (see ``agent/updater.py``).

The socket grants host-level access, hence opt-in. Not for Kubernetes: update the
Deployment image there instead.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from agent.config import Settings

logger = logging.getLogger("ares.agent.selfupdate")

_DOCKER_SOCK = Path("/var/run/docker.sock")
_DOCKER_TIMEOUT = 60.0


def socket_available() -> bool:
    return _DOCKER_SOCK.exists()


async def trigger_self_update(settings: Settings, target_version: str) -> bool:
    """Launch the updater that recreates this container on ``target_version``.

    Best-effort: returns True if the updater was launched, False otherwise (always logged).
    Call once per queued upgrade; a successful run replaces this container."""
    if not socket_available():
        logger.error(
            "Self-update is enabled but %s is not mounted, so the agent cannot update "
            "itself. Mount the Docker socket or upgrade the container manually.",
            _DOCKER_SOCK,
        )
        return False
    if not target_version:
        logger.warning("Update queued but no target version was provided; not self-updating.")
        return False
    transport = httpx.AsyncHTTPTransport(uds=str(_DOCKER_SOCK))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://docker", timeout=_DOCKER_TIMEOUT
        ) as docker:
            base_image = await _own_image(docker, settings.container_name)
            await _launch_updater(docker, settings.container_name, target_version, base_image)
    except (httpx.HTTPError, OSError, KeyError) as exc:
        logger.error("Could not launch the self-update helper: %s", exc)
        return False
    logger.info(
        "Self-update to %s launched; this container is replaced once the new one is healthy.",
        target_version,
    )
    return True


async def _own_image(docker: httpx.AsyncClient, container: str) -> str:
    resp = await docker.get(f"/containers/{container}/json")
    resp.raise_for_status()
    return resp.json()["Config"]["Image"]


async def _launch_updater(
    docker: httpx.AsyncClient, container: str, target_version: str, base_image: str
) -> None:
    """Create + start the one-shot updater from the agent's own image.

    Entrypoint is overridden so the helper runs the updater rather than the agent; it gets
    the socket and the swap parameters, and removes itself when done."""
    body = {
        "Image": base_image,
        "Entrypoint": ["python", "-m", "agent.updater"],
        "Env": [
            f"ARES_UPDATE_CONTAINER={container}",
            f"ARES_UPDATE_TARGET={target_version}",
            f"ARES_UPDATE_BASE_IMAGE={base_image}",
        ],
        "HostConfig": {
            "Binds": [f"{_DOCKER_SOCK}:{_DOCKER_SOCK}"],
            "AutoRemove": True,
        },
    }
    created = await docker.post("/containers/create", json=body)
    created.raise_for_status()
    container_id = created.json()["Id"]
    started = await docker.post(f"/containers/{container_id}/start")
    started.raise_for_status()
