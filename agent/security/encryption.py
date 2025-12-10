"""
Ares Docker Agent - Field-Level Encryption
Uses Fernet (AES-128-CBC with HMAC) for encrypting sensitive database fields.

The encryption key is derived from a master secret that is:
1. Generated on first run
2. Stored in a separate file with restricted permissions
3. Used to derive field-specific keys via HKDF
"""
import base64
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from agent.config import settings

# Master secret file location (inside /data volume, separate from database)
MASTER_SECRET_FILE = "encryption.key"


def _get_master_secret_path() -> Path:
    """Get path to master secret file"""
    return settings.data_dir / MASTER_SECRET_FILE


def _generate_master_secret() -> bytes:
    """Generate a new 32-byte master secret"""
    return secrets.token_bytes(32)


def _load_or_create_master_secret() -> bytes:
    """Load existing master secret or create a new one"""
    secret_path = _get_master_secret_path()

    if secret_path.exists():
        # Load existing secret
        with open(secret_path, 'rb') as f:
            secret = f.read()
        if len(secret) == 32:
            return secret
        # Invalid secret file, regenerate

    # Generate new secret
    secret = _generate_master_secret()

    # Ensure directory exists
    settings.ensure_directories()

    # Write with restricted permissions (owner read/write only)
    # Use os.open with mode flags for atomic creation with permissions
    fd = os.open(
        str(secret_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600  # rw-------
    )
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)

    return secret


def _derive_key(master_secret: bytes, context: str) -> bytes:
    """Derive a Fernet key from master secret using HKDF"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ares-agent-v1",  # Static salt is fine with HKDF
        info=context.encode('utf-8'),
    )
    derived = hkdf.derive(master_secret)
    # Fernet requires base64-encoded 32-byte key
    return base64.urlsafe_b64encode(derived)


def get_fernet(context: str = "default") -> Fernet:
    """
    Get a Fernet instance for encrypting/decrypting data.

    Args:
        context: A string identifying what this key is used for.
                 Different contexts produce different keys from the same master secret.
                 Examples: "wireguard_private_key", "jwt_token"

    Returns:
        Fernet instance for encryption/decryption
    """
    master_secret = _load_or_create_master_secret()
    key = _derive_key(master_secret, context)
    return Fernet(key)


def encrypt_value(plaintext: str, context: str = "default") -> str:
    """
    Encrypt a string value.

    Args:
        plaintext: The string to encrypt
        context: Key derivation context (use different contexts for different data types)

    Returns:
        Base64-encoded encrypted value (prefixed with 'enc:' for identification)
    """
    if not plaintext:
        return plaintext

    fernet = get_fernet(context)
    encrypted = fernet.encrypt(plaintext.encode('utf-8'))
    # Prefix with 'enc:' to identify encrypted values
    return f"enc:{encrypted.decode('utf-8')}"


def decrypt_value(ciphertext: str, context: str = "default") -> str:
    """
    Decrypt an encrypted string value.

    Args:
        ciphertext: The encrypted value (with 'enc:' prefix)
        context: Key derivation context (must match what was used for encryption)

    Returns:
        Decrypted plaintext string

    Raises:
        ValueError: If decryption fails (wrong key, corrupted data, etc.)
    """
    if not ciphertext:
        return ciphertext

    # Check for encryption prefix
    if not ciphertext.startswith("enc:"):
        # Not encrypted, return as-is (for backwards compatibility)
        return ciphertext

    # Remove prefix
    encrypted_data = ciphertext[4:]

    try:
        fernet = get_fernet(context)
        decrypted = fernet.decrypt(encrypted_data.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        raise ValueError("Failed to decrypt value - invalid key or corrupted data")


def is_encrypted(value: str) -> bool:
    """Check if a value is encrypted (has 'enc:' prefix)"""
    return value is not None and value.startswith("enc:")


def rotate_master_secret():
    """
    Rotate the master secret.

    WARNING: This will invalidate all existing encrypted data!
    Only use this if you want to re-encrypt everything.

    Returns the new master secret for backup purposes.
    """
    secret_path = _get_master_secret_path()

    # Delete existing secret
    if secret_path.exists():
        secret_path.unlink()

    # Generate and save new secret
    return _load_or_create_master_secret()
