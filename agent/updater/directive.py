"""Verify a signed update directive from the platform.

This is an AUTHORIZATION + anti-replay layer. It is NOT the root of trust for
code — even a perfectly valid directive still goes through cosign image
verification before anything runs. The checks here stop a network attacker
(without the platform key) from triggering or redirecting updates, and stop a
compromised/confused platform from naming a downgrade, a revoked digest, or a
different registry.
"""
import base64
import json
import logging
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.updater.constants import DIRECTIVE_PUBKEY_PATH, PINNED_REGISTRY

logger = logging.getLogger(__name__)


class DirectiveError(Exception):
    """Raised when a directive fails any authenticity/policy check."""


def _semver(v: str):
    core = (v or "").lstrip("v").split("-", 1)[0].split("+", 1)[0]
    out = []
    for chunk in core.split("."):
        try:
            out.append(int(chunk))
        except ValueError:
            out.append(0)
    return tuple(out) or (0,)


def _semver_lt(a: str, b: str) -> bool:
    return _semver(a) < _semver(b)


def _canonical(payload: dict) -> bytes:
    # Must match the platform's core.update_directive.canonical exactly.
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_pubkey() -> Ed25519PublicKey:
    b64 = os.getenv("ARES_DIRECTIVE_PUBKEY_B64")
    if not b64:
        with open(DIRECTIVE_PUBKEY_PATH, "r") as f:
            b64 = f.read().strip()
    if not b64 or b64.startswith("REPLACE_ME"):
        raise DirectiveError("directive public key not provisioned in this image")
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))


def verify_directive(signed: dict, *, client_nonce: str, agent_id: str, current_version: str) -> dict:
    """Verify signature + policy. Returns the trusted payload, or raises
    DirectiveError. ``current_version`` is this agent's running version, used for
    the anti-downgrade check."""
    if not isinstance(signed, dict) or "payload" not in signed or "signature" not in signed:
        raise DirectiveError("malformed directive envelope")
    if signed.get("alg") != "ed25519":
        raise DirectiveError(f"unexpected signature alg: {signed.get('alg')}")

    payload = signed["payload"]
    try:
        signature = base64.b64decode(signed["signature"])
    except Exception as e:  # noqa: BLE001
        raise DirectiveError(f"bad signature encoding: {e}")

    # 1) Authenticity: signature over the canonical payload.
    try:
        _load_pubkey().verify(signature, _canonical(payload))
    except DirectiveError:
        raise
    except Exception:
        raise DirectiveError("directive signature verification failed")

    # 2) Anti-replay: the directive must echo the nonce WE just sent.
    if payload.get("client_nonce") != client_nonce:
        raise DirectiveError("client_nonce mismatch (possible replay)")

    # 3) Bound to this agent.
    if payload.get("agent_id") != agent_id:
        raise DirectiveError("directive is not addressed to this agent")

    # 4) Registry must be the one we pin (defense in depth vs the cosign check).
    if payload.get("registry") != PINNED_REGISTRY:
        raise DirectiveError(f"registry not pinned: {payload.get('registry')!r}")

    # 5) Target sanity.
    target_version = payload.get("target_version")
    target_digest = payload.get("target_digest")
    if not target_version or not isinstance(target_digest, str) or not target_digest.startswith("sha256:"):
        raise DirectiveError("missing or invalid target_version/target_digest")

    # 6) Anti-downgrade (never install older than we run).
    if _semver_lt(target_version, current_version):
        raise DirectiveError(f"refusing downgrade {current_version} -> {target_version}")

    # 7) Version floor from the directive.
    floor = payload.get("min_acceptable_version")
    if floor and _semver_lt(target_version, floor):
        raise DirectiveError(f"target {target_version} below min acceptable {floor}")

    # 8) Explicit revocation.
    if target_digest in (payload.get("revoked_digests") or []):
        raise DirectiveError("target digest is revoked")

    return payload
