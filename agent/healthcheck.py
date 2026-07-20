"""Container liveness check, shared by the Docker HEALTHCHECK and the k8s liveness probe.

Run as ``python -m agent.healthcheck``: exit 0 (healthy) when the agent refreshed its last-contact
marker within ``max_offline_seconds``, else exit 1 so the runtime restarts a wedged /
network-isolated agent. The marker is written by _record_contact on every successful heartbeat/poll.
"""

from __future__ import annotations

import sys
import time

from agent.config import settings


def is_alive(now: float) -> bool:
    """True when the last-contact marker exists and is newer than max_offline_seconds."""
    marker = settings.data_dir / "last-contact"
    try:
        last_contact = float(marker.read_text())
    except (OSError, ValueError):
        return False  # never written yet, or unreadable/garbage -> treat as not alive
    return now - last_contact < settings.max_offline_seconds


def main() -> int:
    return 0 if is_alive(time.time()) else 1


if __name__ == "__main__":
    sys.exit(main())
