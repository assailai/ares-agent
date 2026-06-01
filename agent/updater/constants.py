"""Updater constants — the trust anchors and the FIXED recreate recipe.

Everything security-critical here is a CONSTANT (or operator-set env), never a
value received over the network. The directive can name a version+digest; it can
never change the registry we pull from, the cosign identity we require, or the
flags the new container runs with.
"""
import os

# --- Pinned image source ----------------------------------------------------
# The ONLY registry/repo the updater will pull from. A directive whose `registry`
# field differs is rejected. Must be a PUBLIC registry so customer hosts can pull
# without Assail credentials (ghcr.io/assailai/* is private; Docker Hub is public).
# The image is cosign-signed on both registries with the same digest + identity.
PINNED_REGISTRY = os.getenv("ARES_AGENT_REGISTRY", "docker.io/assailai/ares-agent")

# --- cosign keyless verification identity (the release workflow) ------------
# These pin WHO signed the image. Keyless cosign verifies a Fulcio cert whose
# SAN is the GitHub Actions workflow identity, logged in Rekor.
COSIGN_OIDC_ISSUER = os.getenv(
    "ARES_COSIGN_OIDC_ISSUER", "https://token.actions.githubusercontent.com"
)
COSIGN_IDENTITY_REGEXP = os.getenv(
    "ARES_COSIGN_IDENTITY_REGEXP",
    r"^https://github\.com/assailai/docker-agent-ares/\.github/workflows/docker-publish\.yml@",
)

# --- Canonical agent container identity + FIXED recreate recipe -------------
AGENT_CONTAINER_NAME = os.getenv("ARES_AGENT_CONTAINER", "ares-agent")
AGENT_DATA_VOLUME = os.getenv("ARES_AGENT_DATA_VOLUME", "ares-agent-data")
AGENT_PORT = 8443
# The agent image is published linux/amd64 only (arm64 disabled). On an arm64
# host (Apple Silicon) docker-py would otherwise resolve the host arch and fail
# with "no matching manifest for linux/arm64". Pin it for pull + run.
AGENT_PLATFORM = os.getenv("ARES_AGENT_PLATFORM", "linux/amd64")

# HostConfig recipe applied to the recreated agent. Constant on purpose: this is
# what stops a forged/compromised directive from recreating the agent with, e.g.,
# a host bind mount or --privileged. Mirrors the documented `docker run` flags.
RECREATE_RECIPE = {
    "user": "root",
    "cap_add": ["NET_ADMIN"],
    "devices": ["/dev/net/tun:/dev/net/tun:rwm"],
    "sysctls": {"net.ipv4.ip_forward": "1"},
    "environment": {"ARES_RUN_AS_ROOT": "true"},
    "volumes": {AGENT_DATA_VOLUME: {"bind": "/data", "mode": "rw"}},
    "restart_policy": {"Name": "unless-stopped"},
}

# --- Loop / robustness knobs ------------------------------------------------
POLL_INTERVAL_SECONDS = int(os.getenv("ARES_UPDATER_POLL_SECONDS", "60"))
HEALTH_TIMEOUT_SECONDS = int(os.getenv("ARES_UPDATER_HEALTH_TIMEOUT", "120"))
HEALTH_POLL_SECONDS = int(os.getenv("ARES_UPDATER_HEALTH_POLL", "3"))
MAX_ATTEMPTS_PER_DIGEST = int(os.getenv("ARES_UPDATER_MAX_ATTEMPTS", "3"))
# Refuse to pull if free disk is below this — avoids bricking the host on a full
# disk mid-pull.
MIN_FREE_DISK_BYTES = int(os.getenv("ARES_UPDATER_MIN_FREE_DISK", str(1_500_000_000)))

# Lock + state files live on the shared /data volume.
DATA_DIR = os.getenv("ARES_DATA_DIR", "/data")
LOCK_PATH = os.path.join(DATA_DIR, "updater.lock")
STATE_PATH = os.path.join(DATA_DIR, "updater_state.json")

# Baked-in Ed25519 public key for directive verification.
DIRECTIVE_PUBKEY_PATH = os.path.join(os.path.dirname(__file__), "..", "keys", "directive_pub.b64")
