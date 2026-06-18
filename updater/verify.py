"""Verify a target image's cosign signature before the updater applies it (fail-closed).

cosign is the root of trust: a tampered version-handoff cannot get malicious code to run,
because the updater refuses any image it cannot verify.
"""

from __future__ import annotations

import logging
import subprocess

from updater.config import UpdaterSettings

logger = logging.getLogger("ares.updater.verify")

_COSIGN_TIMEOUT = 120


def verify(image_ref: str, settings: UpdaterSettings) -> bool:
    """True if ``image_ref`` is acceptable to run. Fail-closed: unknown / unverifiable -> False."""
    if not settings.require_signature:
        logger.warning(
            "Signature verification is DISABLED (dev only); applying %s unverified.", image_ref
        )
        return True

    cmd = ["cosign", "verify", image_ref, "--output", "text"]
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
        return False

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_COSIGN_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("cosign could not run (%s); refusing %s.", exc, image_ref)
        return False
    if result.returncode != 0:
        logger.error("signature verification FAILED for %s: %s", image_ref, result.stderr.strip()[:300])
        return False
    logger.info("signature verified for %s.", image_ref)
    return True
