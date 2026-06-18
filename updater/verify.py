"""Verify a target image's cosign signature and pin it to the verified digest (fail-closed).

cosign is the root of trust: a tampered version-handoff cannot get malicious code to run,
because the updater refuses any image it cannot verify and applies the exact digest cosign
verified, not the mutable tag (which could be repointed between the check and the pull).
"""

from __future__ import annotations

import json
import logging
import subprocess

from updater.config import UpdaterSettings, repo_of

logger = logging.getLogger("ares.updater.verify")

_COSIGN_TIMEOUT = 120


def verify(image_ref: str, settings: UpdaterSettings) -> str | None:
    """The pinned digest ref (``repo@sha256:...``) to apply, or None if the image is not
    acceptable. Pinning to the digest cosign verified closes the verify-then-pull TOCTOU. In
    dev (signature verification off) the tag is returned unpinned."""
    if not settings.require_signature:
        logger.warning(
            "Signature verification is DISABLED (dev only); applying %s unverified.", image_ref
        )
        return image_ref

    cmd = ["cosign", "verify", image_ref, "--output", "json"]
    if settings.cosign_key:
        cmd += ["--key", settings.cosign_key]
    elif settings.cosign_identity and settings.cosign_issuer:
        cmd += [
            "--certificate-identity-regexp",
            settings.cosign_identity,
            "--certificate-oidc-issuer",
            settings.cosign_issuer,
        ]
    else:
        logger.error(
            "require_signature is on but no cosign key or identity is configured; refusing %s.",
            image_ref,
        )
        return None

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_COSIGN_TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("cosign could not run (%s); refusing %s.", exc, image_ref)
        return None
    if result.returncode != 0:
        logger.error(
            "signature verification FAILED for %s: %s", image_ref, result.stderr.strip()[:300]
        )
        return None

    digest = _verified_digest(result.stdout)
    if digest is None:
        logger.error("verified %s but could not read its digest from cosign; refusing.", image_ref)
        return None
    pinned = f"{repo_of(image_ref)}@{digest}"
    logger.info("signature verified for %s (pinned to %s).", image_ref, pinned)
    return pinned


def _verified_digest(cosign_json: str) -> str | None:
    """The manifest digest cosign attested, from ``cosign verify --output json`` (a list of
    verified payloads, each carrying critical.image.docker-manifest-digest)."""
    try:
        digest = json.loads(cosign_json)[0]["critical"]["image"]["docker-manifest-digest"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else None
