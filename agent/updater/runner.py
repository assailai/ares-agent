"""Orchestrates a single verified, rollback-safe agent container swap.

Flow (no value from the directive influences anything but version+digest):
  cosign-verify digest  ->  pull by digest (assert local==target)  ->
  stop old + keep it as a backup  ->  start new (canonical name, published port)
  ->  health-check  ->  on success remove backup; on ANY failure roll back to the
  backup and re-raise.

Guards: a /data file-lock (one update at a time), a per-digest circuit breaker,
and a free-disk check before pulling.

Note (v1 limitation): this swaps the AGENT container. The updater sidecar itself
is replaced out-of-band (compose pull / bootstrap re-run); a slightly stale
updater is harmless because it verifies every release and reads the target from
the platform. Self-replacement of the updater is a documented fast-follow.
"""
import json
import logging
import os
import time

from agent.updater import dockerctl
from agent.updater.constants import (
    AGENT_CONTAINER_NAME,
    MAX_ATTEMPTS_PER_DIGEST,
    PINNED_REGISTRY,
    STATE_PATH,
)
from agent.updater.imageverify import verify_image_digest

logger = logging.getLogger(__name__)


class UpdaterError(Exception):
    pass


def _load_state() -> dict:
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def _save_state(state: dict) -> None:
    try:
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_PATH)
    except Exception as e:  # noqa: BLE001
        logger.warning("could not persist updater state: %s", e)


def circuit_open(digest: str) -> bool:
    """True if we've already failed MAX_ATTEMPTS_PER_DIGEST times for this digest."""
    st = _load_state()
    if st.get("digest") != digest:
        return False
    return int(st.get("attempts", 0)) >= MAX_ATTEMPTS_PER_DIGEST


def _record_attempt(digest: str, ok: bool, error: str = "") -> None:
    st = _load_state()
    if st.get("digest") != digest:
        st = {"digest": digest, "attempts": 0}
    st["attempts"] = int(st.get("attempts", 0)) + 1
    st["last_ok"] = ok
    st["last_error"] = error[:300] if error else ""
    if ok:
        st["last_success_digest"] = digest
    _save_state(st)


def perform_update(payload: dict) -> str:
    """Execute the swap for a verified directive ``payload``. Returns the
    installed image ref on success; raises UpdaterError on failure (after
    rolling back). Caller holds the lock."""
    digest = payload["target_digest"]
    target_version = payload["target_version"]
    image_ref = f"{PINNED_REGISTRY}@{digest}"

    if circuit_open(digest):
        raise UpdaterError(f"circuit breaker open for {digest} (too many failed attempts)")

    client = dockerctl.get_client()

    if not dockerctl.free_disk_ok():
        raise UpdaterError("insufficient free disk for pull")

    # 1) ROOT OF TRUST: cosign verify before pulling anything we'd run.
    verify_image_digest(PINNED_REGISTRY, digest)

    # 2) Pull by digest; asserts the local digest matches (closes TOCTOU).
    dockerctl.pull_by_digest(client, PINNED_REGISTRY, digest)

    old = dockerctl.find_container(client, AGENT_CONTAINER_NAME)
    backup_name = f"{AGENT_CONTAINER_NAME}-prev"

    # Clean any leftover backup from a prior aborted run.
    stale_backup = dockerctl.find_container(client, backup_name)
    if stale_backup:
        dockerctl.stop_and_remove(stale_backup)

    try:
        # 3) Park the old container as a rollback point (don't remove yet).
        if old:
            try:
                old.stop(timeout=20)
            except Exception:  # noqa: BLE001
                pass
            dockerctl.rename(old, backup_name)

        # 4) Start the new agent under the canonical name with the published port.
        new = dockerctl.run_agent_container(
            client, name=AGENT_CONTAINER_NAME, image_ref=image_ref, publish_port=True
        )

        # 5) Health gate.
        if not dockerctl.wait_healthy(new):
            raise UpdaterError("new container failed health check")

        logger.info("update to v%s (%s) succeeded", target_version, digest)
        _record_attempt(digest, ok=True)

    except Exception as e:  # noqa: BLE001 - rollback on ANY failure
        logger.error("update failed (%s) — rolling back", e)
        # Remove the failed new container if present.
        failed = dockerctl.find_container(client, AGENT_CONTAINER_NAME)
        if failed:
            dockerctl.stop_and_remove(failed)
        # Restore the backup to the canonical name and start it.
        backup = dockerctl.find_container(client, backup_name)
        if backup:
            try:
                dockerctl.rename(backup, AGENT_CONTAINER_NAME)
                dockerctl.start(backup)
                logger.info("rollback complete — previous agent restored")
            except Exception as re:  # noqa: BLE001
                logger.error("ROLLBACK FAILED: %s", re)
        _record_attempt(digest, ok=False, error=str(e))
        raise UpdaterError(str(e))

    # 6) Success: drop the backup container (image stays cached for future rollback).
    backup = dockerctl.find_container(client, backup_name)
    if backup:
        dockerctl.stop_and_remove(backup)

    return image_ref
