"""
Ares Docker Agent - WireGuard Configuration Generator
"""
from pathlib import Path
from typing import List, Optional

from agent.config import settings
from agent.database.models import get_config, AgentConfig


def generate_wg_config(
    private_key: str,
    overlay_ip: str,
    gateway_public_key: str,
    gateway_endpoint: str,
    allowed_ips: List[str] = None
) -> str:
    """
    Generate WireGuard configuration file content for use with `wg setconf`.

    Note: This generates a config for `wg setconf`, NOT `wg-quick`.
    The Address is NOT included here as it's not supported by `wg setconf`.
    IP address is assigned separately using `ip addr add`.

    Args:
        private_key: Agent's WireGuard private key (base64)
        overlay_ip: Agent's overlay IP (e.g., "10.200.1.50") - stored but not in config
        gateway_public_key: Gateway's WireGuard public key (base64)
        gateway_endpoint: Gateway's endpoint (e.g., "agents.ares.com:51820")
        allowed_ips: List of allowed IPs/networks (default: ["10.200.0.0/16"])

    Returns:
        WireGuard configuration file content
    """
    if allowed_ips is None:
        allowed_ips = ["10.200.0.0/16"]

    # Note: Address is NOT included - it's a wg-quick extension, not supported by `wg setconf`
    # The manager.py handles IP assignment using `ip addr add`
    config = f"""# Ares Docker Agent WireGuard Configuration
# Generated automatically - do not edit manually
# Note: IP address ({overlay_ip}) is assigned separately via `ip addr add`

[Interface]
PrivateKey = {private_key}

[Peer]
PublicKey = {gateway_public_key}
Endpoint = {gateway_endpoint}
AllowedIPs = {', '.join(allowed_ips)}
PersistentKeepalive = 25
"""
    return config


def write_wg_config(config_content: str, config_path: Path = None) -> Path:
    """
    Write WireGuard configuration to file.

    Args:
        config_content: WireGuard configuration content
        config_path: Path to write config (default: from settings)

    Returns:
        Path to written config file
    """
    config_path = config_path or settings.wireguard_config_path

    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Write config with restrictive permissions
    with open(config_path, 'w') as f:
        f.write(config_content)

    # Set permissions (600 - owner read/write only)
    import os
    os.chmod(config_path, 0o600)

    return config_path


def generate_and_write_config() -> Optional[Path]:
    """
    Generate and write WireGuard config from stored registration data.

    Returns:
        Path to config file, or None if required data is missing
    """
    # Get required values from database
    private_key = get_config(AgentConfig.WIREGUARD_PRIVATE_KEY)
    overlay_ip = get_config(AgentConfig.OVERLAY_IP)
    gateway_public_key = get_config(AgentConfig.GATEWAY_PUBLIC_KEY)
    gateway_endpoint = get_config(AgentConfig.GATEWAY_ENDPOINT)

    if not all([private_key, overlay_ip, gateway_public_key, gateway_endpoint]):
        return None

    # Generate config
    config_content = generate_wg_config(
        private_key=private_key,
        overlay_ip=overlay_ip,
        gateway_public_key=gateway_public_key,
        gateway_endpoint=gateway_endpoint
    )

    # Write config
    return write_wg_config(config_content)


def get_config_path() -> Path:
    """Get the WireGuard config file path"""
    return settings.wireguard_config_path


def config_exists() -> bool:
    """Check if WireGuard config file exists"""
    return settings.wireguard_config_path.exists()
