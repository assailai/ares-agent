"""Optional dashboard-driven self-update (requires the Docker socket).

When the dashboard queues an upgrade and ``ARES_SELF_UPDATE`` is on, the agent launches a
one-shot Watchtower container that pulls the agent's image and recreates this container
with the same configuration. Watchtower does the swap (config replay, restart policy,
rollback on a failed pull) so we do not hand-roll container recreation, which is the part
that could leave a remote agent down.

Self-update tracks the running image tag, so deploy with a moving tag (e.g. ``:latest``)
for new releases to be picked up. Not for Kubernetes: update the Deployment image there.
The socket grants host-level access, hence opt-in.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from agent.config import Settings

logger = logging.getLogger("ares.agent.selfupdate")

_DOCKER_SOCK = Path("/var/run/docker.sock")
# the Docker image-pull stream can be slow on first use; give it room.
_DOCKER_TIMEOUT = 180.0


def socket_available() -> bool:
    return _DOCKER_SOCK.exists()


async def trigger_self_update(settings: Settings) -> bool:
    """Launch a one-shot Watchtower to recreate this container on the new image.

    Best-effort: returns True if the helper was launched, False otherwise (always logged).
    Call this once per queued upgrade; a successful run replaces this container."""
    if not socket_available():
        logger.error(
            "Self-update is enabled but %s is not mounted, so the agent cannot update "
            "itself. Mount the Docker socket or upgrade the container manually.",
            _DOCKER_SOCK,
        )
        return False
    transport = httpx.AsyncHTTPTransport(uds=str(_DOCKER_SOCK))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://docker", timeout=_DOCKER_TIMEOUT
        ) as docker:
            await _launch_watchtower(docker, settings)
    except (httpx.HTTPError, OSError, KeyError) as exc:
        logger.error("Could not launch the self-update helper: %s", exc)
        return False
    logger.info(
        "Self-update launched: Watchtower will pull and recreate %s on the new image. "
        "This container will be replaced.",
        settings.container_name,
    )
    return True


async def _launch_watchtower(docker: httpx.AsyncClient, settings: Settings) -> None:
    """Pull Watchtower, then create + start it as a one-shot updater for our container."""
    await _pull_image(docker, settings.watchtower_image)
    body = {
        "Image": settings.watchtower_image,
        "Cmd": ["--run-once", settings.container_name],
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


async def _pull_image(docker: httpx.AsyncClient, image: str) -> None:
    repo, _, tag = image.rpartition(":")
    if not repo:  # the ref carried no tag
        repo, tag = image, "latest"
    # the response body is a progress stream; reading it to completion finishes the pull.
    resp = await docker.post("/images/create", params={"fromImage": repo, "tag": tag})
    resp.raise_for_status()
    _ = resp.text
