"""
Ares Docker Agent - Health Check Endpoint
"""
from datetime import datetime
from typing import Dict, Any

from agent.database.models import is_setup_completed, get_session as get_db_session, TunnelStatus
from agent.wireguard.manager import get_manager
from agent.registration.client import is_registered


def get_health_status() -> Dict[str, Any]:
    """
    Get comprehensive health status for the agent.
    Used by Docker HEALTHCHECK and dashboard.
    """
    status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "configured": is_setup_completed(),
        "registered": is_registered(),
        "wireguard": get_wireguard_status(),
        "uptime_seconds": get_uptime_seconds()
    }

    # Determine overall health
    if not status["configured"]:
        status["status"] = "unconfigured"
    elif status["wireguard"]["connected"]:
        status["status"] = "healthy"
    elif is_registered():
        status["status"] = "degraded"  # Registered but tunnel down
    else:
        status["status"] = "unhealthy"

    return status


def get_wireguard_status() -> Dict[str, Any]:
    """Get WireGuard tunnel status"""
    db = get_db_session()
    try:
        tunnel = db.query(TunnelStatus).first()
        if tunnel:
            return {
                "connected": tunnel.connected,
                "overlay_ip": tunnel.overlay_ip,
                "last_handshake": tunnel.last_handshake.isoformat() + "Z" if tunnel.last_handshake else None,
                "bytes_sent": tunnel.bytes_sent,
                "bytes_received": tunnel.bytes_received,
                "error": tunnel.error_message
            }
        return {
            "connected": False,
            "overlay_ip": None,
            "last_handshake": None,
            "bytes_sent": 0,
            "bytes_received": 0,
            "error": None
        }
    finally:
        db.close()


def get_uptime_seconds() -> int:
    """Get agent uptime in seconds"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime = float(f.readline().split()[0])
            return int(uptime)
    except Exception:
        return 0


def is_healthy() -> bool:
    """Simple health check for Docker HEALTHCHECK"""
    status = get_health_status()
    return status["status"] in ["healthy", "unconfigured"]
