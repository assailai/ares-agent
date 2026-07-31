"""Companion auto-updater: keep the agent on the version the server marks current.

Reads the desired version from the shared file the agent writes, and on drift verifies the
target image's signature and applies it via the platform (Docker recreate / k8s rolling
update). The agent stays unprivileged; only this updater touches the runtime.
"""

from __future__ import annotations

import json
import logging
import time

from updater import tlsconf, verify
from updater.backend import Backend
from updater.config import repo_of, settings, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend

logger = logging.getLogger("ares.updater")

# k8s wins if both somehow look available (e.g. a socket mounted inside a pod).
_BACKENDS: list[Backend] = [K8sBackend(), DockerBackend()]


def _configure_logging() -> None:
    """Raise the verbosity of ``ares.*`` only, never of the dependencies.

    Same reasoning as the agent's: handing the level to ``basicConfig`` sets the **root** level and
    would enable third-party DEBUG (httpcore traces every request over the docker socket). Root
    stays INFO; only our own loggers follow ``ARES_LOG_LEVEL``.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("ares").setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


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


# in-memory cache of target version -> the digest ref cosign verified for it. Lets a steady
# state skip re-verifying every tick (an updater restart re-verifies once rather than
# re-applying); the updater mounts the shared data dir read-only, so this stays in memory.
_verified: dict[str, str] = {}


def _tick(backend: Backend) -> None:
    target = _read_target()
    if not target:
        return
    running = backend.running_image(settings)
    if running is None or tag_of(running) == target:
        return  # no agent yet, or still on the target version's own tag (initial deploy)
    if _verified.get(target) == running:
        return  # already on the digest we verified for this target

    # the repo is derived from the running agent's image, so the updater can only move to a new
    # tag of the same image the agent already runs (ARES_UPDATE_IMAGE_REPO overrides it).
    image = f"{settings.image_repo or repo_of(running)}:{target}"
    logger.info("update requested: target %s (%s)", target, image)
    pinned = verify.verify(image, settings)  # the verified digest ref, or None (fail-closed)
    if pinned is None:
        return
    _verified[target] = pinned
    if running == pinned:
        return  # already running the verified digest; cache primed, nothing to apply
    backend.apply(settings, pinned)


def main() -> None:
    _configure_logging()
    # Before anything reaches out: cosign is a subprocess, so SSL_CERT_FILE is the only way to
    # hand it the host's CAs on a network that inspects TLS.
    tlsconf.install_ca_bundle()
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
