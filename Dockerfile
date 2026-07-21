# =============================================================================
# Ares Docker Agent - customer-deployable container
# =============================================================================
# Headless, outbound-only: the agent dials ares over HTTPS (control plane) and a
# WebSocket (data-plane tunnel). No inbound ports, no WireGuard, no NET_ADMIN.
#
# Usage (zero-touch: the token carries everything):
#   docker run -d --name ares-agent \
#     -e ARES_TOKEN=<registration-token> \
#     -v ares-agent-data:/data \
#     --restart unless-stopped \
#     assailai/ares-agent:3.2.1
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: build Python wheels
# -----------------------------------------------------------------------------
FROM python:3.12-alpine AS python-builder

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: minimal runtime
# -----------------------------------------------------------------------------
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="Ares Docker Agent"
LABEL org.opencontainers.image.source="https://github.com/assailai/ares-agent"
LABEL org.opencontainers.image.vendor="Assail AI"

# iproute2 gives a full `ip` for LAN auto-detection (busybox's is too limited);
# dash is a small shell for the entrypoint.
RUN apk add --no-cache iproute2 dash openssl \
    && rm -rf /var/cache/apk/* \
    && find /usr -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-compile /wheels/*.whl && rm -rf /wheels

ARG UID=10001
ARG GID=10001
RUN addgroup -g ${GID} ares && adduser -u ${UID} -G ares -h /app -s /sbin/nologin -D ares \
    && mkdir -p /data && chown -R ares:ares /data && chmod 700 /data

WORKDIR /app
COPY --chown=ares:ares agent/ ./agent/
COPY --chown=ares:ares scripts/entrypoint.sh ./entrypoint.sh
RUN chmod 550 /app/entrypoint.sh && chown -R ares:ares /app

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARES_DATA_DIR=/data

# The agent is outbound-only, so no port is published. Liveness reflects real contact with Ares:
# the agent refreshes its last-contact marker on every successful heartbeat/poll, so an agent that
# has gone dark reads unhealthy rather than "up" forever (see agent/healthcheck.py). Under Docker
# the in-process watchdog is what restarts a wedged agent (restart policy acts on exit, not on
# "unhealthy"); this probe drives the k8s liveness restart and honest status.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD python -m agent.healthcheck

VOLUME ["/data"]
USER ares
ENTRYPOINT ["/app/entrypoint.sh"]
