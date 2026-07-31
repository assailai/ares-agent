#!/usr/bin/env bash
# =============================================================================
# End-to-end check that the agent works on a network which inspects TLS.
#
# A real mitmproxy, with its own root CA, sits in front of a stand-in ares and
# re-signs every connection: exactly what a corporate inspecting proxy does. We
# assert both halves of the agent survive it, because they take different code
# paths to the same trust:
#
#   * the control plane (httpx), which is what broke for a customer in July 2026
#   * the data-plane tunnel (websockets, wss://), which live missions depend on
#
# The tunnel check is the one worth having. It drives a real stream through the
# inspected WebSocket to an "internal" host and asserts the payload comes back
# byte for byte, so a pass cannot come from the tunnel merely connecting.
#
# Usage:  bash scripts/e2e_tls_inspection.sh   (needs Docker; pulls python +
#         mitmproxy images and builds the agent from this checkout)
# =============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NET="ares-tls-e2e"
SUBNET="172.29.0.0/16"
ECHO_IP="172.29.0.50"
IMAGE="ares-agent:tls-e2e"
T="$(mktemp -d)"
PASS=0 FAIL=0

cleanup() {
    docker rm -f tls-e2e-echo tls-e2e-ares tls-e2e-proxy tls-e2e-agent >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    rm -rf "$T"
}
trap cleanup EXIT

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# --- the "internal host" the tunnel reaches -----------------------------------
# Reverses what it receives, so a byte-for-byte assertion proves the bytes really
# went through this host and back, not that something echoed them en route.
cat > "$T/echo_server.py" <<'PY'
import asyncio


async def handle(reader, writer):
    data = await reader.read(65536)
    writer.write(data[::-1])
    await writer.drain()
    writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 7000)
    async with server:
        await server.serve_forever()


asyncio.run(main())
PY

# --- the stand-in ares --------------------------------------------------------
# Control plane and tunnel on one port, because that is how the agent derives the
# tunnel URL: tunnel_url() only swaps the scheme on the base URL.
cat > "$T/fake_ares.py" <<'PY'
import json
import os
import struct

from aiohttp import WSMsgType, web

HEADER = struct.Struct(">BQ")
OPEN, OPEN_OK, OPEN_ERR, DATA, CLOSE = 1, 2, 3, 4, 5
TARGET_HOST = os.environ["TARGET_HOST"]
PROBE = b"hello-through-the-inspected-tunnel"

outcome = {"state": "waiting for the agent to open the tunnel"}


def encode(op, sid, payload=b""):
    return HEADER.pack(op, sid) + payload


def decode(frame):
    op, sid = HEADER.unpack_from(frame)
    return op, sid, frame[HEADER.size:]


async def register(request):
    return web.json_response({
        "agent_id": "agt_tls_e2e",
        "agent_token": "tok_tls_e2e",
        "heartbeat_interval_seconds": 5,
        "poll_interval_seconds": 5,
    })


async def heartbeat(request):
    # the flag that makes the agent open the data-plane tunnel, as a running hunt would
    return web.json_response({"tunnel_required": True, "tunnel_allowed_hosts": []})


async def tunnel(request):
    ws = web.WebSocketResponse(max_msg_size=0)
    await ws.prepare(request)
    outcome["state"] = "tunnel connected"
    await ws.send_bytes(encode(OPEN, 1, json.dumps({"host": TARGET_HOST, "port": 7000}).encode()))
    async for msg in ws:
        if msg.type is not WSMsgType.BINARY:
            continue
        op, _, payload = decode(msg.data)
        if op == OPEN_ERR:
            outcome["state"] = "FAILED: the agent refused or could not dial the target"
            break
        if op == OPEN_OK:
            await ws.send_bytes(encode(DATA, 1, PROBE))
        elif op == DATA:
            outcome["state"] = "PASS" if payload == PROBE[::-1] else f"FAILED: got {payload!r}"
            await ws.send_bytes(encode(CLOSE, 1))
            break
    return ws


app = web.Application()
app.add_routes([
    web.post("/api/v1/agent/register", register),
    web.post("/api/v1/agent/heartbeat", heartbeat),
    web.get("/api/v1/agent/tasks", lambda r: web.json_response({"tasks": []})),
    web.get("/api/v1/agent/tunnel", tunnel),
    web.get("/result", lambda r: web.json_response(outcome)),
])
web.run_app(app, host="0.0.0.0", port=8000, print=None)
PY

echo "Building the agent image from this checkout..."
docker build -q -t "$IMAGE" "$REPO_DIR" >/dev/null || { echo "build failed"; exit 1; }

docker network rm "$NET" >/dev/null 2>&1
docker network create --subnet "$SUBNET" "$NET" >/dev/null

echo "Starting the internal host, the stand-in ares, and the inspecting proxy..."
docker run -d --name tls-e2e-echo --network "$NET" --ip "$ECHO_IP" \
    -v "$T/echo_server.py:/echo.py:ro" python:3.12-slim python /echo.py >/dev/null
docker run -d --name tls-e2e-ares --network "$NET" -e TARGET_HOST="$ECHO_IP" \
    -v "$T/fake_ares.py:/fake_ares.py:ro" python:3.12-slim \
    sh -c "pip install -q aiohttp && python /fake_ares.py" >/dev/null

mkdir -p "$T/mitmconf" "$T/hostca" && chmod 777 "$T/mitmconf"
docker run -d --name tls-e2e-proxy --network "$NET" --network-alias fake-ares \
    -v "$T/mitmconf:/home/mitmproxy/.mitmproxy" mitmproxy/mitmproxy \
    mitmdump --mode reverse:http://tls-e2e-ares:8000 --listen-port 8443 >/dev/null

# aiohttp installs on first boot, so wait for the stand-in to actually answer.
for _ in $(seq 1 60); do
    docker run --rm --network "$NET" curlimages/curl -s --max-time 3 \
        http://tls-e2e-ares:8000/result >/dev/null 2>&1 && break
    sleep 2
done
cp "$T/mitmconf/mitmproxy-ca-cert.pem" "$T/hostca/" 2>/dev/null || {
    echo "mitmproxy never wrote its CA; aborting"; exit 1
}

run_agent() {  # $1 = extra docker args ("" for none)
    docker rm -f tls-e2e-agent >/dev/null 2>&1
    # shellcheck disable=SC2086 - $1 is our own flag string, deliberately word-split
    docker run -d --name tls-e2e-agent --network "$NET" \
        -e ARES_TOKEN=t -e ARES_URL=https://fake-ares:8443 -e ARES_NETWORKS="$SUBNET" \
        $1 "$IMAGE" >/dev/null
}

echo
echo "1. Without the host CA mount, the failure should be loud and self-explaining"
run_agent ""
sleep 8
LOG="$(docker logs tls-e2e-agent 2>&1)"
case "$LOG" in
    *CERTIFICATE_VERIFY_FAILED*) ok "TLS verification fails, as it must" ;;
    *) bad "expected CERTIFICATE_VERIFY_FAILED without the mount" ;;
esac
case "$LOG" in
    *"inspecting TLS"*) ok "the error names the remedy instead of only the OpenSSL string" ;;
    *) bad "the certificate error carried no hint" ;;
esac

echo
echo "2. With the host CA mount, and nothing else, both halves should work"
run_agent "-v $T/hostca:/host-ca:ro"
sleep 20
LOG="$(docker logs tls-e2e-agent 2>&1)"
case "$LOG" in
    *"/host-ca (1 file)"*) ok "the startup line reports the host CA it loaded" ;;
    *) bad "the startup line did not report the host CA" ;;
esac
case "$LOG" in
    *"Registered as agent"*) ok "control plane (httpx) verifies through the proxy" ;;
    *) bad "the agent never registered" ;;
esac
case "$LOG" in
    *"tunnel connected"*) ok "data-plane tunnel (wss) verifies through the proxy" ;;
    *) bad "the tunnel never connected" ;;
esac

RESULT="$(docker run --rm --network "$NET" curlimages/curl -s --max-time 10 \
    http://tls-e2e-ares:8000/result 2>/dev/null)"
case "$RESULT" in
    *'"PASS"'*) ok "a real stream round-trips byte for byte through the inspected tunnel" ;;
    *) bad "tunnel round trip: $RESULT" ;;
esac

echo
echo "3. The proxy really terminated and re-signed the WebSocket, rather than passing it through"
case "$(docker logs tls-e2e-proxy 2>&1)" in
    *"WebSocket binary message"*) ok "mitmproxy logged the individual WebSocket frames" ;;
    *) bad "no WebSocket frames in the proxy log; interception is unproven" ;;
esac

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
