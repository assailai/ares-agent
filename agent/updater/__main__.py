"""Updater sidecar entrypoint: ``python -m agent.updater``.

Long-running loop that polls the platform for this agent's signed update
directive and, when one is available and verifies, performs a rollback-safe
container swap. No inbound network; only outbound to the platform (directive),
the registry (pull) and Sigstore (cosign verify).
"""
import logging
import secrets
import time

import fcntl
import httpx

from agent.__version__ import __version__
from agent.config import settings
from agent.database.models import AgentConfig, get_config, init_database
from agent.updater.constants import LOCK_PATH, POLL_INTERVAL_SECONDS
from agent.updater.directive import DirectiveError, verify_directive
from agent.updater.runner import UpdaterError, circuit_open, perform_update

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("agent.updater")

_HTTP_TIMEOUT = 20.0


def _platform_base() -> str:
    return (get_config(AgentConfig.PLATFORM_URL) or "").rstrip("/")


def _auth_token() -> str:
    return get_config(AgentConfig.JWT_TOKEN) or ""


def _agent_id() -> str:
    return get_config(AgentConfig.AGENT_ID) or ""


def _fetch_directive(base: str, token: str, client_nonce: str) -> dict:
    """POST the nonce challenge; return the JSON response (may indicate no update)."""
    url = f"{base}/api/v1/agent/update-directive"
    body = {"client_nonce": client_nonce, "current_version": __version__}
    with httpx.Client(verify=True, timeout=_HTTP_TIMEOUT) as client:
        resp = client.post(url, headers={"Authorization": f"Bearer {token}"}, json=body)
    if resp.status_code == 401:
        raise RuntimeError("auth token invalid/expired")
    if resp.status_code == 503:
        raise RuntimeError("platform update signing not configured")
    if resp.status_code != 200:
        raise RuntimeError(f"directive HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _check_once() -> None:
    base = _platform_base()
    token = _auth_token()
    agent_id = _agent_id()
    if not base or not token or not agent_id:
        logger.debug("agent not registered yet — skipping update check")
        return

    client_nonce = secrets.token_hex(24)
    data = _fetch_directive(base, token, client_nonce)
    if not data.get("update_available"):
        logger.debug("no update available (%s)", data.get("reason", ""))
        return

    signed = data.get("directive")
    if not signed:
        logger.warning("update_available but no directive in response")
        return

    # Verify authenticity + policy (signature, nonce binding, agent binding,
    # pinned registry, anti-downgrade, floor, revocation).
    try:
        payload = verify_directive(
            signed, client_nonce=client_nonce, agent_id=agent_id, current_version=__version__
        )
    except DirectiveError as e:
        logger.error("rejecting update directive: %s", e)
        return

    digest = payload["target_digest"]
    if circuit_open(digest):
        logger.warning("skipping %s — circuit breaker open", digest)
        return

    logger.info("verified directive: -> v%s (%s)", payload["target_version"], digest)

    # Single-update lock (also guards against multiple updater instances).
    lock_f = open(LOCK_PATH, "w")
    try:
        try:
            fcntl.flock(lock_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.info("another update is in progress — skipping")
            return
        try:
            installed = perform_update(payload)
            logger.info("update applied: %s", installed)
        except UpdaterError as e:
            logger.error("update failed: %s", e)
    finally:
        try:
            fcntl.flock(lock_f, fcntl.LOCK_UN)
        finally:
            lock_f.close()


def main() -> None:
    logger.info("🔄 Ares agent updater started (current v%s)", __version__)
    # The DB lives on the shared /data volume; ensure the schema/connection works.
    try:
        init_database()
    except Exception as e:  # noqa: BLE001
        logger.warning("init_database in updater: %s", e)

    while True:
        try:
            _check_once()
        except Exception as e:  # noqa: BLE001
            logger.debug("update check error: %s", e)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
