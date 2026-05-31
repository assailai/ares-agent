#!/bin/sh
# =============================================================================
# Ares Docker Agent - Secure Container Entrypoint
# =============================================================================
# Security: Runs as non-root by default (ares user)
# For WireGuard: run with --user root --cap-add NET_ADMIN, then drops privileges
# =============================================================================

set -e

# Colors for output (works in dash/ash)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
log_warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }

# Version comes from the single source of truth (agent/__version__.py) so the
# banner can never drift from what the agent reports to the platform.
# PYTHONPATH=/app is set in the image, so this resolves from any cwd.
AGENT_VERSION="$(python -c 'from agent.__version__ import __version__; print(__version__)' 2>/dev/null || echo 'unknown')"
log_info "Starting Ares Docker Agent v${AGENT_VERSION}..."

# Updater role: this is the self-update sidecar. It does NO WireGuard/network
# setup and never listens — it only talks to the Docker Engine API (mounted
# socket/pipe) and the platform. Keeping the socket OFF the agent role is the
# core containment decision: a compromise of the network-exposed agent can't
# reach Docker.
if [ "${ARES_ROLE:-agent}" = "updater" ]; then
    log_info "Role=updater — starting self-update loop (no network setup)..."
    cd /app
    exec python -u -m agent.updater
fi

# Detect if running as root
CURRENT_UID=$(id -u)

if [ "$CURRENT_UID" = "0" ]; then
    log_info "Running as root - performing network setup..."

    # =============================================================================
    # Phase 1: Root-only operations (network setup)
    # =============================================================================

    # Ensure data directories exist with correct permissions
    mkdir -p /data/tls /data/wireguard /data/db
    chmod 700 /data/wireguard
    chmod 755 /data /data/tls /data/db
    chown -R "${ARES_UID:-10001}:${ARES_GID:-10001}" /data

    # Check for required capabilities (only when running as root)
    if ip link add dummy0 type dummy 2>/dev/null; then
        ip link delete dummy0 2>/dev/null || true
        log_info "NET_ADMIN capability verified"
    else
        log_warn "NET_ADMIN capability not available. WireGuard VPN may not function."
    fi

    # Enable IP forwarding (required for WireGuard routing)
    # Note: The -w check may pass even if /proc is mounted read-only, so we try the write and catch errors
    if echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
        log_info "IP forwarding enabled"
    else
        log_warn "Cannot enable IP forwarding (read-only /proc or sysctl restriction)."
        log_warn "WireGuard routing to internal networks may not work."
        log_warn "To fix: run container with --sysctl net.ipv4.ip_forward=1"
    fi

    # =============================================================================
    # Phase 2: Run application (optionally drop privileges)
    # =============================================================================

    # Change to app directory
    cd /app

    # Check if we should keep running as root (needed for WireGuard)
    if [ "${ARES_RUN_AS_ROOT:-false}" = "true" ]; then
        log_info "Running as root (ARES_RUN_AS_ROOT=true) - required for WireGuard VPN..."

        # Run startup script as root
        log_info "Running initialization..."
        python -u -m agent.startup

        # Start the FastAPI server as root
        log_info "Starting web server on port ${HTTPS_PORT:-8443}..."
        exec python -u -m agent.main
    else
        log_info "Dropping privileges to user '${ARES_USER:-ares}' (UID: ${ARES_UID:-10001})..."

        # Run startup script as non-root user
        log_info "Running initialization..."
        su-exec "${ARES_USER:-ares}" python -u -m agent.startup

        # Start the FastAPI server as non-root user
        log_info "Starting web server on port ${HTTPS_PORT:-8443}..."
        exec su-exec "${ARES_USER:-ares}" python -u -m agent.main
    fi
else
    # =============================================================================
    # Running as non-root (default, Docker Scout compliant)
    # =============================================================================
    log_info "Running as non-root user (UID: $CURRENT_UID) - Docker Scout compliant mode"
    log_error "============================================================"
    log_error "WARNING: WireGuard VPN will NOT function without root permissions!"
    log_error "============================================================"
    log_error "To enable WireGuard VPN, restart the container with:"
    log_error ""
    log_error "  docker rm -f ares-agent"
    log_error "  docker run -d --name ares-agent \\"
    log_error "    --user root \\"
    log_error "    --cap-add=NET_ADMIN \\"
    log_error "    --device /dev/net/tun:/dev/net/tun \\"
    log_error "    -e ARES_RUN_AS_ROOT=true \\"
    log_error "    -p 8443:8443 \\"
    log_error "    -v ares-agent-data:/data \\"
    log_error "    --restart unless-stopped \\"
    log_error "    assailai/ares-agent:latest"
    log_error ""
    log_error "============================================================"

    # Change to app directory
    cd /app

    # Run startup script
    log_info "Running initialization..."
    python -u -m agent.startup

    # Start the FastAPI server
    log_info "Starting web server on port ${HTTPS_PORT:-8443}..."
    exec python -u -m agent.main
fi
