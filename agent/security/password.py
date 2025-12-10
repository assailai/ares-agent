"""
Ares Docker Agent - Password Security
"""
import re
import secrets
import string
import bcrypt
from typing import Tuple

from agent.config import settings


def generate_password(length: int = 16) -> str:
    """Generate a secure random password"""
    # Ensure at least one of each required character type
    lowercase = secrets.choice(string.ascii_lowercase)
    uppercase = secrets.choice(string.ascii_uppercase)
    digit = secrets.choice(string.digits)
    special = secrets.choice("!@#$%^&*")

    # Fill remaining length with random characters
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    remaining = ''.join(secrets.choice(alphabet) for _ in range(length - 4))

    # Combine and shuffle
    password_chars = list(lowercase + uppercase + digit + special + remaining)
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)


def hash_password(password: str) -> str:
    """Hash password using bcrypt with cost factor 12"""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    Returns (is_valid, error_message)
    """
    min_length = settings.min_password_length

    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)"

    # Check for common weak passwords
    weak_passwords = ['password', '12345678', 'qwerty', 'admin', 'letmein']
    if password.lower() in weak_passwords:
        return False, "Password is too common. Please choose a stronger password."

    return True, ""


def get_password_requirements() -> list:
    """Get list of password requirements for display"""
    return [
        f"At least {settings.min_password_length} characters long",
        "At least one lowercase letter (a-z)",
        "At least one uppercase letter (A-Z)",
        "At least one number (0-9)",
        "At least one special character (!@#$%^&* etc.)"
    ]
