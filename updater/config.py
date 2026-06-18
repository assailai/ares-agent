"""Companion-updater configuration (env-driven, ``ARES_UPDATE_`` prefix)."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class UpdaterSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARES_UPDATE_", extra="ignore")

    # the agent container (docker) / Deployment + container (k8s) this updater keeps current.
    container_name: str = "ares-agent"
    # optional override for the registry/repo; empty means derive it from the running agent's
    # image so the updater can never pull from a different repo than the agent was deployed from.
    image_repo: str = ""
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


def _split_ref(image_ref: str) -> tuple[str, str]:
    """Split an image ref into (repo, tag). A trailing ``:`` is a tag only when what follows
    has no ``/`` (otherwise it is a registry port, e.g. ``reg:5000/img``)."""
    head, sep, tail = image_ref.rpartition(":")
    return (head, tail) if (sep and "/" not in tail) else (image_ref, "")


def tag_of(image_ref: str) -> str:
    """``assailai/ares-agent:2.5.0`` -> ``2.5.0``; empty string when there is no tag."""
    return _split_ref(image_ref)[1]


def repo_of(image_ref: str) -> str:
    """``assailai/ares-agent:2.5.0`` -> ``assailai/ares-agent`` (drops the tag if present)."""
    return _split_ref(image_ref)[0]


settings = UpdaterSettings()
