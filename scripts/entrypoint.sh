#!/bin/sh
# =============================================================================
# Ares Docker Agent - Headless entrypoint (zero-touch)
# =============================================================================
# No web server, no setup wizard. The agent reads ARES_TOKEN from the environment,
# auto-detects its internal LAN(s), registers over HTTPS, then heartbeats + polls.
# WireGuard (data plane) needs --cap-add=NET_ADMIN --device /dev/net/tun; the
# control plane runs fine without them.
# =============================================================================
set -e

log() { printf "[entrypoint] %s\n" "$1"; }

log "Starting Ares Docker Agent (zero-touch)..."

mkdir -p "${ARES_DATA_DIR:-/data}"
cd /app

exec python -u -m agent.main
