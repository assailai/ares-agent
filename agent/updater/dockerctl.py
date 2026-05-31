r"""Thin, intentionally-narrow wrapper over the Docker Engine API (docker-py).

Cross-platform: docker-py talks to the unix socket on Linux/macOS and the
``\\.\pipe\docker_engine`` named pipe on Windows (honouring DOCKER_HOST), so the
same code path serves every host the agent runs on.

Only the operations the updater needs are exposed, and the recreate always uses
the FIXED recipe from constants — nothing here accepts arbitrary HostConfig.
"""
import logging
import shutil
import time

import docker

from agent.updater.constants import (
    AGENT_PORT,
    HEALTH_POLL_SECONDS,
    HEALTH_TIMEOUT_SECONDS,
    MIN_FREE_DISK_BYTES,
    RECREATE_RECIPE,
)

logger = logging.getLogger(__name__)


class DockerOpError(Exception):
    pass


def get_client():
    try:
        return docker.from_env()
    except Exception as e:  # noqa: BLE001
        raise DockerOpError(f"cannot reach Docker Engine: {e}")


def free_disk_ok(path: str = "/") -> bool:
    try:
        return shutil.disk_usage(path).free >= MIN_FREE_DISK_BYTES
    except Exception:  # noqa: BLE001
        # If we can't tell, be conservative and allow (pull failure will surface).
        return True


def pull_by_digest(client, repo: str, digest: str):
    """Pull ``repo@digest`` and assert the local image's digest matches.
    Returns the docker image object. Raises DockerOpError on mismatch — closes
    the verify->run TOCTOU (the verified bytes are exactly what we run)."""
    ref = f"{repo}@{digest}"
    logger.info("pulling %s", ref)
    image = client.images.pull(ref)
    repo_digests = image.attrs.get("RepoDigests", []) or []
    if not any(rd.endswith("@" + digest) for rd in repo_digests):
        raise DockerOpError(
            f"pulled image digest mismatch: wanted {digest}, got {repo_digests}"
        )
    return image


def find_container(client, name: str):
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        return None
    except Exception as e:  # noqa: BLE001
        raise DockerOpError(f"container lookup failed: {e}")


def run_agent_container(client, *, name: str, image_ref: str, publish_port: bool):
    """Create+start an agent container from the FIXED recipe."""
    kwargs = dict(
        image=image_ref,
        name=name,
        detach=True,
        user=RECREATE_RECIPE["user"],
        cap_add=RECREATE_RECIPE["cap_add"],
        devices=RECREATE_RECIPE["devices"],
        sysctls=RECREATE_RECIPE["sysctls"],
        environment=dict(RECREATE_RECIPE["environment"]),
        volumes=dict(RECREATE_RECIPE["volumes"]),
        restart_policy=RECREATE_RECIPE["restart_policy"],
    )
    if publish_port:
        kwargs["ports"] = {f"{AGENT_PORT}/tcp": AGENT_PORT}
    logger.info("starting container %s from %s (publish=%s)", name, image_ref, publish_port)
    return client.containers.run(**kwargs)


def wait_healthy(container, *, timeout: int = HEALTH_TIMEOUT_SECONDS, poll: int = HEALTH_POLL_SECONDS) -> bool:
    """Wait until the container reports healthy via its Docker HEALTHCHECK.
    Falls back to 'running' if the image declares no healthcheck."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            container.reload()
        except Exception:  # noqa: BLE001
            return False
        state = container.attrs.get("State", {}) or {}
        health = (state.get("Health") or {}).get("Status")
        if health == "healthy":
            return True
        if health is None and state.get("Running") and state.get("Status") == "running":
            # No HEALTHCHECK declared — accept running after a short settle.
            time.sleep(poll)
            container.reload()
            st = container.attrs.get("State", {}) or {}
            return bool(st.get("Running"))
        if health == "unhealthy":
            return False
        time.sleep(poll)
    return False


def stop_and_remove(container):
    try:
        container.stop(timeout=20)
    except Exception as e:  # noqa: BLE001
        logger.warning("stop failed for %s: %s", getattr(container, "name", "?"), e)
    try:
        container.remove(force=True)
    except Exception as e:  # noqa: BLE001
        logger.warning("remove failed: %s", e)


def rename(container, new_name: str):
    container.rename(new_name)


def start(container):
    container.start()
