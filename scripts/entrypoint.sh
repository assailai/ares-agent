#!/bin/sh
# =============================================================================
# Ares Docker Agent - Headless entrypoint (zero-touch)
# =============================================================================
# No web server, no setup wizard. The agent reads ARES_TOKEN from the environment,
# auto-detects its internal LAN(s), registers over HTTPS, then heartbeats + polls.
# The data plane is an outbound WebSocket the agent opens while a hunt runs, so no
# inbound ports and no extra capabilities (NET_ADMIN, /dev/net/tun) are needed.
# =============================================================================
set -e

log() { printf "[entrypoint] %s\n" "$1"; }

log "Starting Ares Docker Agent (zero-touch)..."

mkdir -p "${ARES_DATA_DIR:-/data}"
cd /app

exec python -u -m agent.main
