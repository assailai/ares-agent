"""Companion auto-updater: keep the agent on the version the server marks current.

Reads the desired version from the shared file the agent writes, and on drift verifies the
target image's signature and applies it via the platform (Docker recreate / k8s rolling
update). The agent stays unprivileged; only this updater touches the runtime.
"""

from __future__ import annotations

import json
import logging
import time

from updater import verify
from updater.backend import Backend
from updater.config import repo_of, settings, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend

logger = logging.getLogger("ares.updater")

# k8s wins if both somehow look available (e.g. a socket mounted inside a pod).
_BACKENDS: list[Backend] = [K8sBackend(), DockerBackend()]


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _pick_backend() -> Backend | None:
    return next((backend for backend in _BACKENDS if backend.available()), None)


def _read_target() -> str | None:
    try:
        raw = settings.target_file.read_text()
    except OSError:
        return None  # not written yet: no update is queued
    try:
        return json.loads(raw).get("version") or None
    except ValueError:
        logger.warning("ignoring malformed update target at %s", settings.target_file)
        return None


def _target_image(backend: Backend, target_version: str) -> str | None:
    """The image to move to, or None if there is nothing to do (no agent yet / already there).

    The repo is derived from the running agent's image, so the updater can only pull a new tag
    of the same image the agent already runs (ARES_UPDATE_IMAGE_REPO overrides it)."""
    running = backend.running_image(settings)
    if running is None or tag_of(running) == target_version:
        return None
    repo = settings.image_repo or repo_of(running)
    return f"{repo}:{target_version}"


def _tick(backend: Backend) -> None:
    target = _read_target()
    if not target:
        return
    image = _target_image(backend, target)
    if image is None:
        return
    logger.info("update requested: target %s (%s)", target, image)
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
        "%s watching %s (every %ss)",
        type(backend).__name__,
        settings.container_name,
        settings.poll_seconds,
    )
    while True:
        try:
            _tick(backend)
        except Exception as exc:  # noqa: BLE001 - keep the updater alive through any transient error
            logger.error("update check failed: %s", exc)
        time.sleep(settings.poll_seconds)


if __name__ == "__main__":
    main()
