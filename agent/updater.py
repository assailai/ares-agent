"""Self-update helper: recreate the agent container on a pinned target version.

Runs as a one-shot ``python -m agent.updater`` inside a short-lived container that the
running agent launches over the Docker socket, so it outlives the agent during the swap.

Fail-safe: the replacement is started and verified to stay up BEFORE the old container is
removed, so a bad target version leaves the running agent untouched (worst case: the update
does not apply, logged). The new container reuses the old one's full config (env, volumes,
restart policy, network) with only the image tag swapped.

Env in:
  ARES_UPDATE_CONTAINER   the agent container name to replace (e.g. "ares-agent")
  ARES_UPDATE_TARGET      the version to move to (e.g. "2.5.0")
  ARES_UPDATE_BASE_IMAGE  the agent's current image ref (to derive the repository)
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s ares.agent.updater %(message)s"
)
logger = logging.getLogger("ares.agent.updater")

_SOCK = "/var/run/docker.sock"
_TIMEOUT = 300.0
# the replacement must stay up across these checks before we retire the old container.
_VERIFY_CHECKS = 5
_VERIFY_INTERVAL = 2.0


def target_image(base_image: str, version: str) -> str:
    """``ghcr.io/x/ares-agent:2.4.0`` + ``2.5.0`` -> ``ghcr.io/x/ares-agent:2.5.0``."""
    head, sep, tail = base_image.rpartition(":")
    # a ":" only separates a tag when the tail has no "/" (otherwise it is a registry port).
    repo = base_image if (not sep or "/" in tail) else head
    return f"{repo}:{version}"


async def _pull(docker: httpx.AsyncClient, image_ref: str) -> None:
    repo, _, tag = image_ref.rpartition(":")
    resp = await docker.post("/images/create", params={"fromImage": repo, "tag": tag})
    resp.raise_for_status()
    _ = resp.text  # drain the progress stream so the pull completes


async def _running(docker: httpx.AsyncClient, cid: str) -> bool:
    resp = await docker.get(f"/containers/{cid}/json")
    resp.raise_for_status()
    return bool(resp.json()["State"]["Running"])


async def run() -> int:
    container = os.environ["ARES_UPDATE_CONTAINER"]
    version = os.environ["ARES_UPDATE_TARGET"]
    base_image = os.environ["ARES_UPDATE_BASE_IMAGE"]
    target_ref = target_image(base_image, version)
    next_name = f"{container}-next"

    transport = httpx.AsyncHTTPTransport(uds=_SOCK)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://docker", timeout=_TIMEOUT
    ) as docker:
        logger.info("updating %s to %s", container, target_ref)
        await _pull(docker, target_ref)

        old = await docker.get(f"/containers/{container}/json")
        old.raise_for_status()
        attrs = old.json()

        # clear any leftover from a prior aborted run, then start the replacement with the
        # old container's config and only the image swapped.
        await docker.delete(f"/containers/{next_name}", params={"force": "true"})
        body = {**attrs["Config"], "Image": target_ref, "HostConfig": attrs["HostConfig"]}
        created = await docker.post("/containers/create", params={"name": next_name}, json=body)
        created.raise_for_status()
        cid = created.json()["Id"]
        (await docker.post(f"/containers/{cid}/start")).raise_for_status()

        for _ in range(_VERIFY_CHECKS):
            await asyncio.sleep(_VERIFY_INTERVAL)
            if not await _running(docker, cid):
                logger.error(
                    "replacement %s did not stay up; aborting, the old agent keeps running",
                    next_name,
                )
                await docker.delete(f"/containers/{cid}", params={"force": "true"})
                return 1

        # healthy: retire the old container and give its name to the replacement.
        await docker.delete(f"/containers/{container}", params={"force": "true"})
        await docker.post(f"/containers/{cid}/rename", params={"name": container})
        logger.info("update complete: %s now runs %s", container, target_ref)
    return 0


def main() -> None:
    try:
        raise SystemExit(asyncio.run(run()))
    except Exception as exc:  # noqa: BLE001 - log and exit non-zero; the old agent is untouched
        logger.error("self-update failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
