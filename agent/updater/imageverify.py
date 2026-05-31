"""cosign image-signature verification — the ROOT OF TRUST for self-update.

The updater refuses to run any image whose digest is not signed by the release
workflow's keyless identity (Fulcio cert + Rekor transparency log). Even if the
platform, the directive-signing key, and the network are all compromised, an
attacker cannot get malicious code to run here without also compromising
Sigstore + the GitHub Actions OIDC identity of the release workflow.

Requires the ``cosign`` binary on PATH (baked into the image) and outbound
access to the Sigstore transparency log for keyless verification.
"""
import logging
import subprocess

from agent.updater.constants import COSIGN_IDENTITY_REGEXP, COSIGN_OIDC_ISSUER

logger = logging.getLogger(__name__)


class ImageVerifyError(Exception):
    """Raised when cosign verification fails or cannot be performed."""


def verify_image_digest(repo: str, digest: str, *, timeout: int = 120) -> None:
    """cosign-verify ``repo@digest`` against the pinned keyless identity.

    Raises ImageVerifyError on any failure (unsigned, wrong signer, cosign
    missing, network/Rekor failure). Fail-closed — the caller must NOT proceed
    if this raises.
    """
    ref = f"{repo}@{digest}"
    cmd = [
        "cosign",
        "verify",
        "--certificate-oidc-issuer",
        COSIGN_OIDC_ISSUER,
        "--certificate-identity-regexp",
        COSIGN_IDENTITY_REGEXP,
        ref,
    ]
    logger.info("cosign verifying %s", ref)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        raise ImageVerifyError("cosign binary not found in image")
    except subprocess.TimeoutExpired:
        raise ImageVerifyError("cosign verification timed out")

    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "").strip()
        raise ImageVerifyError(f"cosign verification failed: {msg[:500]}")
    logger.info("cosign verification OK for %s", ref)
