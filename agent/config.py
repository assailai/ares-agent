"""Ares Docker Agent configuration (zero-touch, environment-driven).

One command brings the agent up: ``docker run -e ARES_TOKEN=... ghcr.io/assailai/ares-agent``.
Everything else has a sensible default. There is no interactive setup wizard.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARES_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # One-time registration token minted in the Ares dashboard (Settings -> Agents).
    # REQUIRED: the agent exits with a clear message if it is missing.
    token: str = ""
    # Base URL of the Ares control plane.
    url: str = "https://api.assailai.com"
    # Optional comma-separated CIDRs that override auto-detected internal networks.
    networks: str = ""
    # Optional friendly name shown in the dashboard (defaults to the host's name).
    agent_name: str = ""
    # Skip TLS verification. LOCAL DEV ONLY (e.g. plain http or a self-signed ares-v2).
    insecure: bool = False

    log_level: str = "INFO"
    data_dir: Path = Field(default=Path("/data"))
    agent_version: str = "2.4.0"

    # Self-update (opt-in): on a dashboard-queued upgrade, recreate this container on the
    # version the dashboard marks current (a pinned tag), via a short-lived updater helper.
    # Needs the Docker socket mounted, which grants host-level access, so it is off by default.
    self_update: bool = False
    container_name: str = "ares-agent"

    @property
    def base_url(self) -> str:
        return self.url.rstrip("/")

    @property
    def state_path(self) -> Path:
        return self.data_dir / "agent-state.json"

    def network_overrides(self) -> list[str]:
        return [n.strip() for n in self.networks.split(",") if n.strip()]


settings = Settings()
