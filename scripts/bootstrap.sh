#!/usr/bin/env bash
# =============================================================================
# Ares Docker Agent - Bootstrap Script
# =============================================================================
# Zero-touch installer: checks Docker, starts the agent and its auto-update companion, waits until
# the agent reports online. Cross-platform (macOS, Linux, Windows Git Bash / WSL). Set
# ARES_DISABLE_AUTOUPDATE to install the agent alone (no self-update).
#
# Usage:
#   ARES_TOKEN=<token> bash scripts/bootstrap.sh
#   bash scripts/bootstrap.sh <token>
#   bash <(curl -fsSL https://raw.githubusercontent.com/assailai/ares-agent/main/scripts/bootstrap.sh)
#
# Optional env (passed through to the container when set): ARES_URL,
# ARES_NETWORKS, ARES_AGENT_NAME, ARES_INSECURE, ARES_SCAN_SCOPE.
# =============================================================================

set -euo pipefail

# Defaults to the current pinned release; override with ARES_VERSION=X.Y.Z or ARES_IMAGE=<full ref>.
IMAGE="${ARES_IMAGE:-assailai/ares-agent:${ARES_VERSION:-3.1.0}}"
# The companion updater keeps the agent on the release the dashboard marks current; it is the only
# component that touches the Docker socket (the agent stays unprivileged). Set ARES_DISABLE_AUTOUPDATE
# to opt out (change-control-sensitive hosts). Override the image with ARES_UPDATER_IMAGE=<full ref>.
UPDATER_IMAGE="${ARES_UPDATER_IMAGE:-assailai/ares-updater:${ARES_VERSION:-3.1.0}}"
CONTAINER_NAME="ares-agent"
UPDATER_CONTAINER_NAME="ares-updater"
VOLUME_NAME="ares-agent-data"
ONLINE_TIMEOUT=120
ONLINE_INTERVAL=3

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
step()  { printf "\n${BLUE}${BOLD}==> %s${NC}\n" "$1"; }

detect_platform() {
    case "$(uname -s)" in
        Darwin) PLATFORM="macos" ;;
        Linux)  grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && PLATFORM="wsl" || PLATFORM="linux" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        *) PLATFORM="unknown" ;;
    esac
}

check_docker() {
    step "Checking Docker"
    if ! command -v docker >/dev/null 2>&1; then
        error "Docker is not installed. Install Docker Desktop or Docker Engine: https://docs.docker.com/get-docker/"
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        case "$PLATFORM" in
            linux) error "Docker daemon is not running. Run: sudo systemctl start docker" ;;
            *)     error "Docker daemon is not running. Start Docker Desktop and try again." ;;
        esac
        exit 1
    fi
    info "Docker is ready ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'unknown'))."
}

resolve_token() {
    # Precedence: positional argument, then ARES_TOKEN env, then interactive prompt.
    TOKEN="${1:-${ARES_TOKEN:-}}"
    if [ -z "$TOKEN" ] && [ -t 0 ]; then
        printf "Paste your registration token (from the dashboard, Settings -> Agents): "
        read -r TOKEN
    fi
    if [ -z "$TOKEN" ]; then
        error "No registration token provided. Pass it as ARES_TOKEN=... or as the first argument."
        exit 1
    fi
}

replace_existing() {
    local name="$1"
    docker ps -a --format '{{.Names}}' | grep -q "^${name}$" || return 0
    warn "A container named '${name}' already exists; replacing it (the data volume is kept)."
    docker rm -f "$name" >/dev/null 2>&1 || true
}

start_container() {
    step "Starting the agent"
    replace_existing "$CONTAINER_NAME"

    local run_args=(-d --name "$CONTAINER_NAME" -e "ARES_TOKEN=$TOKEN")

    # On native Linux (Docker Engine) run on the host network so the agent sees the real interfaces
    # and auto-scopes the LAN with no extra config. Docker Desktop (macOS/Windows/WSL) runs Linux
    # containers in a VM where host networking would bind to that VM, not the machine, so we stay on
    # bridge there: the agent still enrolls and comes online (the LAN is scanned from a Linux host).
    if [ "$PLATFORM" = "linux" ]; then
        run_args+=(--network host)
    fi

    local var
    for var in ARES_URL ARES_NETWORKS ARES_AGENT_NAME ARES_INSECURE ARES_SCAN_SCOPE; do
        [ -n "${!var:-}" ] && run_args+=(-e "$var=${!var}")
    done
    run_args+=(-v "${VOLUME_NAME}:/data" --restart unless-stopped)

    if ! docker run "${run_args[@]}" "$IMAGE" >/dev/null; then
        error "Failed to start the container. Try: docker pull $IMAGE"
        exit 1
    fi
    info "Container started."
}

start_updater() {
    if [ -n "${ARES_DISABLE_AUTOUPDATE:-}" ]; then
        info "Auto-update disabled (ARES_DISABLE_AUTOUPDATE set); the agent will not self-update."
        return 0
    fi
    step "Starting the auto-update companion"
    replace_existing "$UPDATER_CONTAINER_NAME"
    # Only the updater touches the Docker socket; it recreates the agent on a new, cosign-verified
    # image when the dashboard marks a release current (the signer identity is baked into the image).
    # Non-fatal: if it cannot start (e.g. no socket access), the agent still runs, just without
    # auto-update.
    if docker run -d --name "$UPDATER_CONTAINER_NAME" \
        -e "ARES_UPDATE_CONTAINER=$CONTAINER_NAME" \
        -v "${VOLUME_NAME}:/data:ro" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --restart unless-stopped "$UPDATER_IMAGE" >/dev/null 2>&1; then
        info "Auto-update companion started."
    else
        warn "Could not start the ares-updater companion; the agent will run but will not auto-update."
        warn "Check Docker socket access, or pull it manually with: docker pull $UPDATER_IMAGE"
    fi
}

wait_until_online() {
    step "Waiting for the agent to come online"
    local elapsed=0 logs
    while [ "$elapsed" -lt "$ONLINE_TIMEOUT" ]; do
        if [ "$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null)" = "exited" ]; then
            error "The agent exited unexpectedly. Recent logs:"
            docker logs --tail 20 "$CONTAINER_NAME" 2>&1
            exit 1
        fi
        logs="$(docker logs "$CONTAINER_NAME" 2>&1 || true)"
        case "$logs" in
            *"Agent online"*)
                printf "\n"; info "The agent is online."; return 0 ;;
            *"Registration token rejected"*)
                printf "\n"; error "The registration token was rejected (expired or already used). Generate a fresh one in the dashboard."; exit 1 ;;
            *"Refusing to start"*)
                printf "\n"; error "The agent refused to start. Recent logs:"; docker logs --tail 20 "$CONTAINER_NAME" 2>&1; exit 1 ;;
        esac
        printf "  waiting... %ds/%ds   \r" "$elapsed" "$ONLINE_TIMEOUT"
        sleep "$ONLINE_INTERVAL"
        elapsed=$((elapsed + ONLINE_INTERVAL))
    done
    printf "\n"
    warn "The agent did not report online within ${ONLINE_TIMEOUT}s. It may still be retrying."
    warn "Follow its progress with: docker logs -f $CONTAINER_NAME"
}

print_summary() {
    printf "\n"
    info "Done. The agent now appears in your Ares dashboard under Settings -> Agents."
    printf "\n"
    info "Useful commands:"
    info "  docker logs -f ares-agent     follow the agent's logs"
    info "  docker restart ares-agent     restart the agent"
    info "  docker rm -f ares-agent       stop and remove it (the data volume is kept)"
    if [ -z "${ARES_DISABLE_AUTOUPDATE:-}" ]; then
        info "  docker logs -f ares-updater   follow the auto-update companion"
    fi
}

main() {
    printf "\n${BOLD}Ares Docker Agent - Bootstrap${NC}\n================================\n"
    detect_platform
    check_docker
    resolve_token "$@"
    start_container
    start_updater
    wait_until_online
    print_summary
}

main "$@"
