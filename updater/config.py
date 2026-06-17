"""Companion-updater configuration (env-driven, ``ARES_UPDATE_`` prefix)."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class UpdaterSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_UPDATE_", extra="ignore")

    # the agent container (docker) / Deployment + container (k8s) this updater keeps current.
    container_name: str = "ares-agent"
    # the registry/repo the agent image lives in; the target version tag is appended.
    image_repo: str = "ghcr.io/assailai/ares-agent"
    # shared with the agent: the agent writes the desired version here, the updater reads it.
    target_file: Path = Field(default=Path("/data/update-target.json"))
    poll_seconds: float = 30.0

    # fail-closed: refuse to apply an image whose signature we cannot verify. Turn this OFF
    # (ARES_UPDATE_REQUIRE_SIGNATURE=false) only for local/dev, before image signing is wired.
    require_signature: bool = True
    # cosign keyless verification (preferred): the expected signer identity + OIDC issuer.
    cosign_identity: str = ""
    cosign_issuer: str = ""
    # cosign key-based verification (alternative): path to a cosign public key.
    cosign_key: str = ""

    # k8s namespace override; defaults to the pod's own namespace (service-account file).
    k8s_namespace: str = ""
    log_level: str = "INFO"

    def image_for(self, version: str) -> str:
        return f"{self.image_repo}:{version}"


def tag_of(image_ref: str) -> str:
    """``ghcr.io/x/ares-agent:2.5.0`` -> ``2.5.0``; a ``:`` is a tag only when the tail has
    no ``/`` (otherwise it is a registry port). Empty string when there is no tag."""
    head, sep, tail = image_ref.rpartition(":")
    return "" if (not sep or "/" in tail) else tail


settings = UpdaterSettings()
