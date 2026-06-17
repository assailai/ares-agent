"""The platform backend contract the updater applies through (Docker or Kubernetes)."""

from __future__ import annotations

from typing import Protocol

from updater.config import UpdaterSettings


class Backend(Protocol):
    def available(self) -> bool:
        """True if this backend can run here (the Docker socket / an in-cluster service account)."""
        ...

    def running_image(self, settings: UpdaterSettings) -> str | None:
        """The image ref the agent is currently running, or None if it is not deployed yet."""
        ...

    def apply(self, settings: UpdaterSettings, image_ref: str) -> None:
        """Move the agent to ``image_ref`` (recreate the container / patch the Deployment)."""
        ...
