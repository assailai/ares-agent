"""Companion auto-updater: keep the agent on the version the server marks current.

Reads the desired version from the shared file the agent writes, and on drift verifies the
target image's signature and applies it via the platform (Docker recreate / k8s rolling
update). The agent stays unprivileged; only this updater touches the runtime.
"""

from __future__ import annotations

import json
import logging
import time

from updater import dockerd, kube, verify
from updater.config import settings

logger = logging.getLogger("ares.updater")


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _pick_backend():
    """k8s if we have a service account, else Docker if we have the socket, else None."""
    if kube.available():
        logger.info("kubernetes mode (patching the Deployment)")
        return kube
    if dockerd.available():
        logger.info("docker mode (recreating the container)")
        return dockerd
    return None


def _read_target() -> str | None:
    try:
        return json.loads(settings.target_file.read_text()).get("version") or None
    except (OSError, ValueError):
        return None  # not written yet, or no update requested


def _tick(backend) -> None:
    target = _read_target()
    if not target:
        return
    running = backend.running_version(settings)
    if running == target:
        return
    image = settings.image_for(target)
    logger.info("update requested: running=%s target=%s (%s)", running, target, image)
    if not verify.verify(image, settings):
        return  # fail-closed: leave the agent on its current version
    backend.apply(settings, image)


def main() -> None:
    _configure_logging()
    backend = _pick_backend()
    if backend is None:
        logger.error(
            "no Docker socket and not running in Kubernetes; the updater cannot apply updates."
        )
        raise SystemExit(1)
    logger.info(
        "ares-updater watching %s (every %ss)", settings.container_name, settings.poll_seconds
    )
    while True:
        try:
            _tick(backend)
        except Exception as exc:  # noqa: BLE001 - keep the updater alive through any transient error
            logger.error("update check failed: %s", exc)
        time.sleep(settings.poll_seconds)


if __name__ == "__main__":
    main()
