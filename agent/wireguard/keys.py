"""
Ares Docker Agent - WireGuard Key Generation
Uses Curve25519 for key generation (same as WireGuard)
"""
import base64
from nacl.public import PrivateKey
from typing import Tuple

from agent.database.models import get_config, set_config, AgentConfig


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a new WireGuard keypair using Curve25519.
    Returns (private_key_base64, public_key_base64)
    """
    # Generate private key
    private_key = PrivateKey.generate()

    # Derive public key
    public_key = private_key.public_key

    # Encode as base64 (WireGuard format)
    private_key_b64 = base64.b64encode(bytes(private_key)).decode('utf-8')
    public_key_b64 = base64.b64encode(bytes(public_key)).decode('utf-8')

    return private_key_b64, public_key_b64


def get_or_create_keypair() -> Tuple[str, str]:
    """
    Get existing keypair from database, or generate a new one.
    Returns (private_key_base64, public_key_base64)
    """
    private_key = get_config(AgentConfig.WIREGUARD_PRIVATE_KEY)
    public_key = get_config(AgentConfig.WIREGUARD_PUBLIC_KEY)

    if private_key and public_key:
        return private_key, public_key

    # Generate new keypair
    private_key, public_key = generate_keypair()

    # Store in database
    set_config(AgentConfig.WIREGUARD_PRIVATE_KEY, private_key, encrypted=True)
    set_config(AgentConfig.WIREGUARD_PUBLIC_KEY, public_key)

    return private_key, public_key


def get_public_key() -> str:
    """Get the agent's WireGuard public key"""
    _, public_key = get_or_create_keypair()
    return public_key


def get_private_key() -> str:
    """Get the agent's WireGuard private key"""
    private_key, _ = get_or_create_keypair()
    return private_key


def validate_wireguard_key(key: str) -> bool:
    """Validate a WireGuard public key format"""
    try:
        decoded = base64.b64decode(key)
        # WireGuard keys are 32 bytes
        return len(decoded) == 32
    except Exception:
        return False
