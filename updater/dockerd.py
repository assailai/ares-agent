"""Docker backend: read the running agent version and recreate it on a target image.

Fail-safe: the replacement is started and verified to stay up BEFORE the old container is
removed, so a bad target never takes the agent down. The agent never has the socket; only
this updater does.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import httpx

from updater.config import UpdaterSettings, tag_of

logger = logging.getLogger("ares.updater.docker")

_SOCK = Path("/var/run/docker.sock")
_TIMEOUT = 300.0
# the replacement must stay up across these checks before we retire the old container.
_VERIFY_CHECKS = 5
_VERIFY_INTERVAL = 2.0


def available() -> bool:
    return _SOCK.exists()


def _client() -> httpx.Client:
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(_SOCK)), base_url="http://docker", timeout=_TIMEOUT
    )


def running_version(settings: UpdaterSettings) -> str | None:
    with _client() as docker:
        resp = docker.get(f"/containers/{settings.container_name}/json")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return tag_of(resp.json()["Config"]["Image"]) or None


def apply(settings: UpdaterSettings, image_ref: str) -> None:
    name = settings.container_name
    next_name = f"{name}-next"
    with _client() as docker:
        _pull(docker, image_ref)
        old = docker.get(f"/containers/{name}/json")
        old.raise_for_status()
        attrs = old.json()

        # clear any leftover from a prior aborted run, then start the replacement with the
        # old container's config and only the image swapped.
        docker.delete(f"/containers/{next_name}", params={"force": "true"})
        body = {**attrs["Config"], "Image": image_ref, "HostConfig": attrs["HostConfig"]}
        created = docker.post("/containers/create", params={"name": next_name}, json=body)
        created.raise_for_status()
        cid = created.json()["Id"]
        docker.post(f"/containers/{cid}/start").raise_for_status()

        if not _stays_up(docker, cid):
            logger.error("replacement did not stay up; aborting, the old agent keeps running")
            docker.delete(f"/containers/{cid}", params={"force": "true"})
            return

        # healthy: retire the old container and give its name to the replacement.
        docker.delete(f"/containers/{name}", params={"force": "true"})
        docker.post(f"/containers/{cid}/rename", params={"name": name})
        logger.info("updated %s to %s", name, image_ref)


def _stays_up(docker: httpx.Client, cid: str) -> bool:
    """True if the replacement keeps running across the verify window (not crash-looping)."""
    for _ in range(_VERIFY_CHECKS):
        time.sleep(_VERIFY_INTERVAL)
        if not _running(docker, cid):
            return False
    return True


def _pull(docker: httpx.Client, image_ref: str) -> None:
    repo, _, tag = image_ref.rpartition(":")
    # the body is a progress stream; a normal post reads it to completion (= pull finished).
    docker.post("/images/create", params={"fromImage": repo, "tag": tag}).raise_for_status()


def _running(docker: httpx.Client, cid: str) -> bool:
    resp = docker.get(f"/containers/{cid}/json")
    resp.raise_for_status()
    return bool(resp.json()["State"]["Running"])
