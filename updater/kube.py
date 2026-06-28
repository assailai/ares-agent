"""Kubernetes backend: read the agent Deployment's image and patch it to a target image.

Patching the Deployment triggers a native rolling update (and k8s owns the rollback via
``kubectl rollout undo``). The updater runs as a sidecar with a ServiceAccount scoped to
get/patch only the agent Deployment.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

from updater.config import UpdaterSettings

logger = logging.getLogger("ares.updater.k8s")

_SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_TIMEOUT = 60.0


class K8sBackend:
    def available(self) -> bool:
        return bool(os.environ.get("KUBERNETES_SERVICE_HOST")) and (_SA / "token").exists()

    def running_image(self, settings: UpdaterSettings) -> str | None:
        namespace = _namespace(settings)
        with _client() as kube:
            resp = kube.get(_deployment_path(namespace, settings.container_name))
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            containers = resp.json()["spec"]["template"]["spec"]["containers"]
        return next((c["image"] for c in containers if c["name"] == settings.container_name), None)

    def apply(self, settings: UpdaterSettings, image_ref: str) -> None:
        namespace = _namespace(settings)
        # strategic-merge patch: set only the agent container's image; k8s rolls the Deployment.
        patch = {
            "spec": {
                "template": {
                    "spec": {"containers": [{"name": settings.container_name, "image": image_ref}]}
                }
            }
        }
        with _client() as kube:
            resp = kube.patch(
                _deployment_path(namespace, settings.container_name),
                json=patch,
                headers={"Content-Type": "application/strategic-merge-patch+json"},
            )
            resp.raise_for_status()
        logger.info(
            "patched Deployment %s/%s image to %s; kubernetes will roll it out",
            namespace,
            settings.container_name,
            image_ref,
        )


def _namespace(settings: UpdaterSettings) -> str:
    return settings.k8s_namespace or (_SA / "namespace").read_text().strip()


def _client() -> httpx.Client:
    token = (_SA / "token").read_text().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    return httpx.Client(
        base_url=f"https://{host}:{port}",
        headers={"Authorization": f"Bearer {token}"},
        verify=str(_SA / "ca.crt"),
        timeout=_TIMEOUT,
    )


def _deployment_path(namespace: str, name: str) -> str:
    return f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
