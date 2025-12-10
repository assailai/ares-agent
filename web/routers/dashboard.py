"""
Ares Docker Agent - Dashboard Routes
"""
import json
from pathlib import Path
from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from agent.database.models import (
    is_setup_completed,
    get_config,
    set_config,
    get_recent_audit_logs,
    add_audit_log,
    AuditLog,
    AgentConfig
)
from agent.security.session import validate_session
from agent.health.checker import get_health_status, get_wireguard_status
from agent.registration.client import get_registration_status, deregister
from agent.wireguard.manager import get_manager

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_auth(request: Request) -> bool:
    """Check if user is authenticated"""
    session_id = request.session.get("session_id")
    return session_id and validate_session(session_id)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, message: str = None, error: str = None):
    """Show main dashboard"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    if not is_setup_completed():
        return RedirectResponse(url="/setup", status_code=302)

    # Get status information
    health = get_health_status()
    registration = get_registration_status()
    wireguard = get_wireguard_status()
    audit_logs = get_recent_audit_logs(20)

    # Get internal networks
    networks_json = get_config(AgentConfig.INTERNAL_NETWORKS, "[]")
    try:
        internal_networks = json.loads(networks_json)
    except json.JSONDecodeError:
        internal_networks = []

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "message": message,
        "error": error,
        "health": health,
        "registration": registration,
        "wireguard": wireguard,
        "internal_networks": internal_networks,
        "audit_logs": audit_logs,
        "agent_name": get_config(AgentConfig.AGENT_NAME, "Ares Agent"),
        "platform_url": get_config(AgentConfig.PLATFORM_URL, "")
    })


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, message: str = None, error: str = None):
    """Show settings page"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    if not is_setup_completed():
        return RedirectResponse(url="/setup", status_code=302)

    registration = get_registration_status()

    # Get internal networks
    networks_json = get_config(AgentConfig.INTERNAL_NETWORKS, "[]")
    try:
        internal_networks = json.loads(networks_json)
    except json.JSONDecodeError:
        internal_networks = []

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "message": message,
        "error": error,
        "registration": registration,
        "internal_networks": internal_networks,
        "agent_name": get_config(AgentConfig.AGENT_NAME, ""),
        "platform_url": get_config(AgentConfig.PLATFORM_URL, "")
    })


@router.post("/settings/agent-name")
async def update_agent_name(request: Request, agent_name: str = Form(...)):
    """Update agent name"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    agent_name = agent_name.strip()
    if len(agent_name) < 3:
        return RedirectResponse(url="/settings?error=Agent+name+must+be+at+least+3+characters", status_code=302)

    set_config(AgentConfig.AGENT_NAME, agent_name)
    add_audit_log(AuditLog.ACTION_SETTINGS_UPDATED, f"Agent name: {agent_name}", get_client_ip(request))

    return RedirectResponse(url="/settings?message=Agent+name+updated", status_code=302)


@router.post("/settings/networks")
async def update_networks(request: Request, internal_networks: str = Form(...)):
    """Update internal networks"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    import ipaddress

    # Parse and validate networks
    networks = []
    for line in internal_networks.strip().split("\n"):
        network = line.strip()
        if not network:
            continue

        try:
            ipaddress.ip_network(network, strict=False)
            networks.append(network)
        except ValueError:
            return RedirectResponse(
                url=f"/settings?error=Invalid+CIDR+notation:+{network}",
                status_code=302
            )

    if not networks:
        return RedirectResponse(url="/settings?error=Please+enter+at+least+one+network", status_code=302)

    set_config(AgentConfig.INTERNAL_NETWORKS, json.dumps(networks))
    add_audit_log(AuditLog.ACTION_NETWORKS_UPDATED, f"Networks: {networks}", get_client_ip(request))

    return RedirectResponse(url="/settings?message=Networks+updated.+Restart+tunnel+to+apply+changes.", status_code=302)


@router.post("/tunnel/restart")
async def restart_tunnel(request: Request):
    """Restart WireGuard tunnel"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    manager = get_manager()
    success = await manager.restart()

    if success:
        add_audit_log(AuditLog.ACTION_TUNNEL_CONNECTED, "Tunnel restarted", get_client_ip(request))
        return RedirectResponse(url="/dashboard?message=Tunnel+restarted+successfully", status_code=302)
    else:
        return RedirectResponse(url="/dashboard?error=Failed+to+restart+tunnel", status_code=302)


@router.post("/tunnel/stop")
async def stop_tunnel(request: Request):
    """Stop WireGuard tunnel"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    manager = get_manager()
    await manager.stop()

    add_audit_log(AuditLog.ACTION_TUNNEL_DISCONNECTED, "Tunnel stopped manually", get_client_ip(request))
    return RedirectResponse(url="/dashboard?message=Tunnel+stopped", status_code=302)


@router.post("/disconnect")
async def disconnect_from_platform(request: Request, confirm: str = Form(...)):
    """Disconnect from Ares platform"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    if confirm.lower() != "disconnect":
        return RedirectResponse(url="/settings?error=Please+type+DISCONNECT+to+confirm", status_code=302)

    # Stop tunnel
    manager = get_manager()
    await manager.stop()

    # Deregister
    await deregister()

    add_audit_log(AuditLog.ACTION_TUNNEL_DISCONNECTED, "Disconnected from platform", get_client_ip(request))

    return RedirectResponse(url="/setup?step=1&message=Disconnected.+You+can+now+reconfigure+the+agent.", status_code=302)


@router.get("/logs", response_class=HTMLResponse)
async def view_logs(request: Request):
    """View all audit logs"""
    if not require_auth(request):
        return RedirectResponse(url="/login", status_code=302)

    audit_logs = get_recent_audit_logs(100)

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "audit_logs": audit_logs
    })
