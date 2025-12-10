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

log_info "Starting Ares Docker Agent v1.0.5..."

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
    if [ -w /proc/sys/net/ipv4/ip_forward ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        log_info "IP forwarding enabled"
    else
        log_warn "Cannot enable IP forwarding (read-only /proc). WireGuard routing may not work."
    fi

    # =============================================================================
    # Phase 2: Drop privileges and run as non-root user
    # =============================================================================

    log_info "Dropping privileges to user '${ARES_USER:-ares}' (UID: ${ARES_UID:-10001})..."

    # Change to app directory
    cd /app

    # Run startup script as non-root user
    log_info "Running initialization..."
    su-exec "${ARES_USER:-ares}" python -u -m agent.startup

    # Start the FastAPI server as non-root user
    log_info "Starting web server on port ${HTTPS_PORT:-8443}..."
    exec su-exec "${ARES_USER:-ares}" python -u -m agent.main
else
    # =============================================================================
    # Running as non-root (default, Docker Scout compliant)
    # =============================================================================
    log_info "Running as non-root user (UID: $CURRENT_UID) - Docker Scout compliant mode"
    log_warn "WireGuard VPN requires root. For full functionality, run with: docker run --user root --cap-add NET_ADMIN ..."

    # Change to app directory
    cd /app

    # Run startup script
    log_info "Running initialization..."
    python -u -m agent.startup

    # Start the FastAPI server
    log_info "Starting web server on port ${HTTPS_PORT:-8443}..."
    exec python -u -m agent.main
fi
