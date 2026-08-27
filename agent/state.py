"""Durable agent identity, persisted as a single JSON file.

A deployed agent needs to remember two things: who it is (its id + bearer token), and which
registration token that identity was minted from. The file is written 0600 so the token is not
world-readable.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

_lock = threading.Lock()


def fingerprint(registration_token: str) -> str:
    """A stable, non-reversible label for a registration token.

    Only ever compared against another fingerprint: never sent anywhere, and never logged. The
    question it answers is "did the operator re-run the installer with the same token, or a
    different one?", and a hash settles that without keeping a second copy of the secret on disk.
    """
    return hashlib.sha256(registration_token.encode()).hexdigest()


@dataclass
class AgentState:
    agent_id: str | None = None
    agent_token: str | None = None  # bearer token presented on every control-plane call
    # Which ARES_TOKEN this identity is already accounted for by. Two cases share the field: the
    # registration token that minted the identity, or - when a *different* token was presented
    # and the control plane refused it as spent - that refused one, recorded so the agent does
    # not re-present a dead token on every container restart. At the one place this is read the
    # meaning is the same either way: "presenting this token again would tell us nothing new".
    # None for a state file written before the field existed; see minted_with.
    registration_token_fingerprint: str | None = None

    @property
    def registered(self) -> bool:
        return bool(self.agent_id and self.agent_token)

    def minted_with(self, registration_token: str) -> bool:
        """True if this identity is already accounted for by ``registration_token``.

        Deliberately False for a state file that predates the field: that is what makes an
        upgrading agent present its stored token exactly once and record the answer, rather than
        either re-enrolling on every restart or never noticing a new token again.
        """
        if not self.registration_token_fingerprint:
            return False
        return self.registration_token_fingerprint == fingerprint(registration_token)


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
