"""
Ares Docker Agent - Session Management
"""
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

from agent.config import settings
from agent.database.models import Session, get_session as get_db_session, AdminUser


def generate_session_id() -> str:
    """Generate a new session ID (UUID)"""
    return str(uuid.uuid4())


def generate_secret_key() -> str:
    """Generate a cryptographically secure secret key"""
    return secrets.token_hex(32)


def create_session(ip_address: str = None, user_agent: str = None) -> str:
    """Create a new session and return the session ID"""
    session_id = generate_session_id()
    expires_at = datetime.utcnow() + timedelta(hours=settings.session_expire_hours)

    db = get_db_session()
    try:
        session = Session(
            id=session_id,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(session)
        db.commit()
        return session_id
    finally:
        db.close()


def validate_session(session_id: str) -> bool:
    """Validate a session ID and check if it's still active"""
    if not session_id:
        return False

    db = get_db_session()
    try:
        session = db.query(Session).filter(Session.id == session_id).first()
        if not session:
            return False

        if session.is_expired():
            # Clean up expired session
            db.delete(session)
            db.commit()
            return False

        return True
    finally:
        db.close()


def destroy_session(session_id: str) -> bool:
    """Destroy a session (logout)"""
    if not session_id:
        return False

    db = get_db_session()
    try:
        session = db.query(Session).filter(Session.id == session_id).first()
        if session:
            db.delete(session)
            db.commit()
            return True
        return False
    finally:
        db.close()


def destroy_all_sessions():
    """Destroy all sessions (e.g., after password change)"""
    db = get_db_session()
    try:
        db.query(Session).delete()
        db.commit()
    finally:
        db.close()


def cleanup_expired_sessions():
    """Remove all expired sessions"""
    db = get_db_session()
    try:
        now = datetime.utcnow()
        db.query(Session).filter(Session.expires_at < now).delete()
        db.commit()
    finally:
        db.close()


def get_admin_user() -> Optional[AdminUser]:
    """Get the admin user (there's only one)"""
    db = get_db_session()
    try:
        return db.query(AdminUser).first()
    finally:
        db.close()


def create_admin_user(password_hash: str, must_change_password: bool = True) -> AdminUser:
    """Create the admin user"""
    db = get_db_session()
    try:
        # Delete existing admin user if any
        db.query(AdminUser).delete()

        admin = AdminUser(
            password_hash=password_hash,
            must_change_password=must_change_password
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        return admin
    finally:
        db.close()


def update_admin_password(new_password_hash: str, must_change: bool = False) -> bool:
    """Update admin user password. Returns True if successful."""
    import logging
    logger = logging.getLogger(__name__)

    db = get_db_session()
    try:
        admin = db.query(AdminUser).first()
        if admin:
            admin.password_hash = new_password_hash
            admin.must_change_password = must_change
            admin.updated_at = datetime.utcnow()
            db.commit()
            logger.info("Admin password updated successfully")
            return True
        else:
            logger.error("Cannot update password: no admin user found in database")
            return False
    except Exception as e:
        logger.error(f"Failed to update admin password: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def record_login_attempt(success: bool, ip_address: str = None):
    """Record a login attempt"""
    db = get_db_session()
    try:
        admin = db.query(AdminUser).first()
        if admin:
            if success:
                admin.failed_attempts = 0
                admin.locked_until = None
                admin.last_login = datetime.utcnow()
            else:
                admin.failed_attempts += 1
                if admin.failed_attempts >= settings.max_login_attempts:
                    admin.lock_account(settings.lockout_minutes)
            db.commit()
    finally:
        db.close()


def is_account_locked() -> Tuple[bool, Optional[datetime]]:
    """Check if admin account is locked. Returns (is_locked, locked_until)"""
    db = get_db_session()
    try:
        admin = db.query(AdminUser).first()
        if admin and admin.is_locked():
            return True, admin.locked_until
        return False, None
    finally:
        db.close()
