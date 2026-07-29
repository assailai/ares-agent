"""Ares Docker Agent configuration (zero-touch, environment-driven).

One command brings the agent up: ``docker run -e ARES_TOKEN=... assailai/ares-agent``.
Everything else has a sensible default. There is no interactive setup wizard.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from agent.__version__ import __version__


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARES_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # One-time registration token minted in the Ares dashboard (Settings -> Agents).
    # REQUIRED: the agent exits with a clear message if it is missing.
    # SecretStr, not str, so the value cannot reach a log by accident: this settings object is the
    # one place the enrollment token lives, and a plain str would render in full through any
    # `repr(settings)` or unhandled pydantic validation error. Read it with `.get_secret_value()`.
    token: SecretStr = SecretStr("")
    # Base URL of the Ares control plane.
    url: str = "https://api.assailai.com"
    # Optional comma-separated CIDRs that override auto-detected internal networks.
    networks: str = ""
    # Optional friendly name shown in the dashboard (defaults to the host's name).
    agent_name: str = ""
    # Skip TLS verification. LOCAL DEV ONLY (e.g. plain http or a self-signed ares-v2).
    insecure: bool = False

    # how broadly to scan when ARES_NETWORKS is unset: "supernet16" (default; each attached
    # subnet widened to its enclosing /16), "attached" (interface prefixes only), "rfc1918" (all
    # private ranges, each capped at scan_max_hosts and logged, so the largest are partial --
    # opt-in, slow), or "host-all" (supernet16 plus the docker bridge subnets and the host
    # loopback -- for a container run with host networking). See agent.netdetect.
    scan_scope: str = "supernet16"
    # max simultaneous TCP connects. Clamped at startup to what the file-descriptor budget allows.
    scan_concurrency: int = 2048
    # per-connect timeout (seconds) for the phase-2 full port sweep on a live host.
    scan_connect_timeout: float = 1.0
    # faster per-connect timeout (seconds) for the phase-1 liveness sweep across every host.
    scan_discovery_timeout: float = 0.5
    # hosts are scanned this prefix at a time (a /24 by default) for bounded memory + live progress.
    scan_chunk_prefix: int = 24
    # safety ceiling on hosts scanned per task; truncation beyond this is logged, never silent.
    scan_max_hosts: int = 262_144

    # If the agent cannot successfully reach Ares (heartbeat or task poll) for this long, it exits
    # so the container runtime restarts it fresh: a new process re-resolves DNS and rebuilds its
    # client, recovering from a wedged / network-isolated state that in-loop retries cannot (e.g. a
    # thread pool starved by hung DNS lookups). Generous, so a brief blip self-heals without a
    # restart (10 min is roughly 20 missed 30s heartbeats).
    max_offline_seconds: int = Field(default=600, ge=60, le=86400)

    log_level: str = "INFO"
    data_dir: Path = Field(default=Path("/data"))
    # single source of truth lives in agent/__version__.py
    agent_version: str = Field(default=__version__)

    @property
    def base_url(self) -> str:
        return self.url.rstrip("/")

    @property
    def state_path(self) -> Path:
        return self.data_dir / "agent-state.json"

    @property
    def update_target_path(self) -> Path:
        # the companion updater reads this from the shared data dir; the agent only writes it.
        return self.data_dir / "update-target.json"

    def network_overrides(self) -> list[str]:
        return [n.strip() for n in self.networks.split(",") if n.strip()]


settings = Settings()
