"""
Ares Docker Agent - WireGuard Process Manager
Manages wireguard-go userspace implementation
"""
import asyncio
import subprocess
import os
import re
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

from agent.config import settings
from agent.database.models import (
    get_session as get_db_session,
    TunnelStatus,
    add_audit_log,
    AuditLog
)
from agent.wireguard.config_gen import generate_and_write_config, config_exists

logger = logging.getLogger(__name__)


class WireGuardManager:
    """Manager for WireGuard tunnel using wireguard-go"""

    def __init__(self):
        self.interface = settings.wireguard_interface
        self.config_path = settings.wireguard_config_path
        self._process: Optional[subprocess.Popen] = None
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> bool:
        """
        Start the WireGuard tunnel.
        Returns True if successful.
        """
        if self._running:
            logger.warning("WireGuard tunnel already running")
            return True

        # Ensure config exists
        if not config_exists():
            config_path = generate_and_write_config()
            if not config_path:
                logger.error("Cannot start WireGuard: configuration not available")
                self._update_status(connected=False, error="Configuration not available")
                return False

        try:
            # Create WireGuard interface - prefer kernel module over wireguard-go
            logger.info(f"Starting WireGuard interface: {self.interface}")

            # First, try to remove any existing interface
            subprocess.run(
                ["ip", "link", "del", "dev", self.interface],
                capture_output=True,
                check=False
            )

            # Try native kernel module first (ip link add type wireguard)
            result = subprocess.run(
                ["ip", "link", "add", "dev", self.interface, "type", "wireguard"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                # Kernel module not available, fall back to wireguard-go
                logger.info(f"Kernel WireGuard not available (error: {result.stderr.strip()}), trying wireguard-go")

                # Create environment with flags to suppress kernel warning and run in foreground
                # WG_PROCESS_FOREGROUND=1 suppresses the "kernel has first class support" warning
                wg_env = os.environ.copy()
                wg_env["WG_PROCESS_FOREGROUND"] = "1"

                logger.info(f"Starting wireguard-go with WG_PROCESS_FOREGROUND=1")
                self._process = subprocess.Popen(
                    ["wireguard-go", "-f", self.interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=wg_env
                )

                # Wait a moment for interface to come up
                await asyncio.sleep(1)

                # Check if process is still running
                if self._process.poll() is not None:
                    stderr = self._process.stderr.read().decode() if self._process.stderr else ""
                    logger.error(f"wireguard-go failed to start: {stderr}")
                    self._update_status(connected=False, error=f"Failed to start: {stderr}")
                    return False
            else:
                logger.info("Using native kernel WireGuard module")
                self._process = None  # No process for kernel module

            # Apply configuration using wg setconf
            result = subprocess.run(
                ["wg", "setconf", self.interface, str(self.config_path)],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Failed to apply WireGuard config: {result.stderr}")
                await self.stop()
                self._update_status(connected=False, error=f"Config error: {result.stderr}")
                return False

            # Bring interface up
            result = subprocess.run(
                ["ip", "link", "set", "up", "dev", self.interface],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Failed to bring up interface: {result.stderr}")
                await self.stop()
                self._update_status(connected=False, error=f"Interface error: {result.stderr}")
                return False

            # Get overlay IP from config and add to interface
            overlay_ip = self._get_overlay_ip_from_config()
            if overlay_ip:
                result = subprocess.run(
                    ["ip", "addr", "add", overlay_ip, "dev", self.interface],
                    capture_output=True,
                    text=True
                )
                # Ignore error if address already exists

            self._running = True
            self._update_status(connected=True)
            add_audit_log(AuditLog.ACTION_TUNNEL_CONNECTED, f"Interface: {self.interface}")

            # Start monitoring task
            self._monitor_task = asyncio.create_task(self._monitor_loop())

            logger.info("WireGuard tunnel started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start WireGuard: {e}")
            self._update_status(connected=False, error=str(e))
            return False

    async def stop(self) -> bool:
        """Stop the WireGuard tunnel"""
        self._running = False

        # Cancel monitor task
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        # Terminate wireguard-go process
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

        # Remove interface
        try:
            subprocess.run(
                ["ip", "link", "del", "dev", self.interface],
                capture_output=True,
                check=False
            )
        except Exception as e:
            logger.warning(f"Failed to remove interface: {e}")

        self._update_status(connected=False)
        add_audit_log(AuditLog.ACTION_TUNNEL_DISCONNECTED, f"Interface: {self.interface}")

        logger.info("WireGuard tunnel stopped")
        return True

    async def restart(self) -> bool:
        """Restart the WireGuard tunnel"""
        await self.stop()
        await asyncio.sleep(1)
        return await self.start()

    def is_running(self) -> bool:
        """Check if tunnel is currently running"""
        if not self._running:
            return False
        # For kernel module, check if interface exists
        if self._process is None:
            result = subprocess.run(
                ["ip", "link", "show", "dev", self.interface],
                capture_output=True
            )
            return result.returncode == 0
        # For wireguard-go, check if process is alive
        return self._process.poll() is None

    def get_status(self) -> Dict[str, Any]:
        """Get current tunnel status"""
        status = {
            "connected": False,
            "overlay_ip": None,
            "last_handshake": None,
            "bytes_sent": 0,
            "bytes_received": 0,
            "error": None
        }

        if not self.is_running():
            return status

        try:
            # Parse wg show output
            result = subprocess.run(
                ["wg", "show", self.interface],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                output = result.stdout
                status["connected"] = True

                # Parse last handshake
                handshake_match = re.search(r'latest handshake: (.+)', output)
                if handshake_match:
                    status["last_handshake"] = handshake_match.group(1)

                # Parse transfer stats
                transfer_match = re.search(r'transfer: ([\d.]+\s+\w+) received, ([\d.]+\s+\w+) sent', output)
                if transfer_match:
                    status["bytes_received"] = self._parse_bytes(transfer_match.group(1))
                    status["bytes_sent"] = self._parse_bytes(transfer_match.group(2))

            # Get overlay IP
            result = subprocess.run(
                ["ip", "-o", "addr", "show", "dev", self.interface],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    status["overlay_ip"] = ip_match.group(1)

        except Exception as e:
            logger.error(f"Failed to get tunnel status: {e}")
            status["error"] = str(e)

        return status

    async def _monitor_loop(self):
        """Background task to monitor tunnel health"""
        while self._running:
            try:
                status = self.get_status()
                self._update_status(
                    connected=status["connected"],
                    overlay_ip=status.get("overlay_ip"),
                    bytes_sent=status.get("bytes_sent", 0),
                    bytes_received=status.get("bytes_received", 0),
                    error=status.get("error")
                )

                # Parse and store last handshake
                if status.get("last_handshake") and status["last_handshake"] != "none":
                    # Handshake exists, tunnel is healthy
                    pass

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

            await asyncio.sleep(30)  # Check every 30 seconds

    def _update_status(
        self,
        connected: bool,
        overlay_ip: str = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        error: str = None
    ):
        """Update tunnel status in database"""
        db = get_db_session()
        try:
            status = db.query(TunnelStatus).first()
            if not status:
                status = TunnelStatus()
                db.add(status)

            status.connected = connected
            if overlay_ip:
                status.overlay_ip = overlay_ip
            status.bytes_sent = bytes_sent
            status.bytes_received = bytes_received
            status.error_message = error
            status.updated_at = datetime.utcnow()

            if connected:
                status.last_handshake = datetime.utcnow()

            db.commit()
        finally:
            db.close()

    def _get_overlay_ip_from_config(self) -> Optional[str]:
        """Get overlay IP from database (not config file since wg setconf doesn't support Address)"""
        from agent.database.models import get_config, AgentConfig
        try:
            overlay_ip = get_config(AgentConfig.OVERLAY_IP)
            if overlay_ip:
                # Ensure it has CIDR notation
                if "/" not in overlay_ip:
                    overlay_ip = f"{overlay_ip}/16"
                return overlay_ip
        except Exception:
            pass
        return None

    def _parse_bytes(self, size_str: str) -> int:
        """Parse byte size string (e.g., '1.5 MiB') to bytes"""
        try:
            parts = size_str.strip().split()
            if len(parts) != 2:
                return 0

            value = float(parts[0])
            unit = parts[1].upper()

            multipliers = {
                'B': 1,
                'KIB': 1024,
                'MIB': 1024**2,
                'GIB': 1024**3,
                'TIB': 1024**4,
                'KB': 1000,
                'MB': 1000**2,
                'GB': 1000**3,
                'TB': 1000**4,
            }

            return int(value * multipliers.get(unit, 1))
        except Exception:
            return 0


# Global instance
_manager: Optional[WireGuardManager] = None


def get_manager() -> WireGuardManager:
    """Get the global WireGuard manager instance"""
    global _manager
    if _manager is None:
        _manager = WireGuardManager()
    return _manager
