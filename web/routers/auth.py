"""
Ares Docker Agent - Authentication Routes
"""
from pathlib import Path
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from agent.database.models import add_audit_log, AuditLog
from agent.security.password import verify_password, validate_password_strength, hash_password, get_password_requirements
from agent.security.session import (
    get_admin_user,
    create_session,
    destroy_session,
    validate_session,
    is_account_locked,
    record_login_attempt,
    update_admin_password,
    destroy_all_sessions
)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None, message: str = None):
    """Show login page"""
    # Check if already logged in
    session_id = request.session.get("session_id")
    if session_id and validate_session(session_id):
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "message": message
    })


@router.post("/login")
async def login(request: Request, password: str = Form(...)):
    """Handle login form submission"""
    client_ip = get_client_ip(request)

    # Check if account is locked
    locked, locked_until = is_account_locked()
    if locked:
        add_audit_log(AuditLog.ACTION_LOGIN_FAILED, "Account locked", client_ip, success=False)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"Account is locked. Please try again later."
        })

    # Get admin user
    admin = get_admin_user()
    if not admin:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "No admin user configured. Please restart the agent."
        })

    # Verify password
    if not verify_password(password, admin.password_hash):
        record_login_attempt(success=False, ip_address=client_ip)
        add_audit_log(AuditLog.ACTION_LOGIN_FAILED, "Invalid password", client_ip, success=False)

        # Check if now locked
        locked, _ = is_account_locked()
        if locked:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Too many failed attempts. Account is now locked for 30 minutes."
            })

        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid password"
        })

    # Successful login
    record_login_attempt(success=True, ip_address=client_ip)
    add_audit_log(AuditLog.ACTION_LOGIN, "Successful login", client_ip)

    # Create session
    session_id = create_session(
        ip_address=client_ip,
        user_agent=request.headers.get("User-Agent")
    )
    request.session["session_id"] = session_id

    return RedirectResponse(url="/", status_code=302)


@router.get("/logout")
async def logout(request: Request):
    """Handle logout"""
    session_id = request.session.get("session_id")
    if session_id:
        destroy_session(session_id)
        add_audit_log(AuditLog.ACTION_LOGOUT, ip_address=get_client_ip(request))

    request.session.clear()
    return RedirectResponse(url="/login?message=Logged+out+successfully", status_code=302)


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, error: str = None):
    """Show change password page"""
    # Require login
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "error": error,
        "password_requirements": get_password_requirements()
    })


@router.post("/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Handle password change"""
    session_id = request.session.get("session_id")
    if not session_id or not validate_session(session_id):
        return RedirectResponse(url="/login", status_code=302)

    client_ip = get_client_ip(request)

    # Get admin user
    admin = get_admin_user()
    if not admin:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "No admin user configured",
            "password_requirements": get_password_requirements()
        })

    # Verify current password
    if not verify_password(current_password, admin.password_hash):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "Current password is incorrect",
            "password_requirements": get_password_requirements()
        })

    # Check passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "New passwords do not match",
            "password_requirements": get_password_requirements()
        })

    # Validate password strength
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": error_msg,
            "password_requirements": get_password_requirements()
        })

    # Update password - MUST check return value!
    new_hash = hash_password(new_password)
    if not update_admin_password(new_hash, must_change=False):
        # Password update failed - keep the old password valid
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "Failed to update password. Please try again.",
            "password_requirements": get_password_requirements()
        })

    # Only clear the initial password AFTER successful update
    from agent.database.models import set_config, AgentConfig
    set_config(AgentConfig.INITIAL_PASSWORD, "")

    # Destroy all sessions (force re-login)
    destroy_all_sessions()

    add_audit_log(AuditLog.ACTION_PASSWORD_CHANGED, ip_address=client_ip)

    return RedirectResponse(url="/login?message=Password+changed+successfully.+Please+login+again.", status_code=302)
