"""Durable agent identity, persisted as a single JSON file.

Replaces the old SQLite/admin store: a deployed agent only needs to remember who it is
(its id + bearer token). Written 0600 so the token is not world-readable.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

_lock = threading.Lock()


@dataclass
class AgentState:
    agent_id: str | None = None
    agent_token: str | None = None  # bearer token presented on every control-plane call

    @property
    def registered(self) -> bool:
        return bool(self.agent_id and self.agent_token)


def load_state(path: Path) -> AgentState:
    if path.exists():
        try:
            known = {f for f in AgentState.__dataclass_fields__}
            data = {k: v for k, v in json.loads(path.read_text()).items() if k in known}
            return AgentState(**data)
        except (ValueError, OSError, TypeError):
            pass
    return AgentState()


def save_state(path: Path, state: AgentState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(state), indent=2))
        tmp.chmod(0o600)
        tmp.replace(path)
