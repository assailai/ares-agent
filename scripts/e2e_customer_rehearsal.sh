#!/usr/bin/env bash
# =============================================================================
# Rehearse a real customer install on a TLS-inspecting network, end to end.
#
# e2e_tls_inspection.sh proves the mechanism. This proves the *deployment*: a
# Debian host with its own Docker daemon, the customer's root CA installed the
# way their IT installs it (update-ca-certificates), an inspecting proxy signing
# with that same root, and then the untouched bootstrap.sh doing what the
# dashboard's recommended one-liner does. No flags, no hand-holding.
#
# The negative control is the point. The same host runs the previously released
# agent and must still fail, otherwise the environment is not reproducing the bug
# and a pass here would mean nothing.
#
# Usage:  bash scripts/e2e_customer_rehearsal.sh   (needs Docker; runs a
#         privileged Docker-in-Docker container and pulls a few images)
# =============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HOST=allstate-sim            # stands in for the customer's machine
PRIOR_RELEASE=assailai/ares-agent:3.3.3   # the negative control
T="$(mktemp -d)"
PASS=0 FAIL=0

cleanup() { docker rm -f "$HOST" >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
inhost() { docker exec "$HOST" bash -c "$1"; }

sed -n '/^cat > "\$T\/echo_server.py"/,/^PY$/p' "$REPO_DIR/scripts/e2e_tls_inspection.sh" \
    | sed '1d;$d' > "$T/echo_server.py"
sed -n '/^cat > "\$T\/fake_ares.py"/,/^PY$/p' "$REPO_DIR/scripts/e2e_tls_inspection.sh" \
    | sed '1d;$d' > "$T/fake_ares.py"
cp "$REPO_DIR/scripts/bootstrap.sh" "$T/"

echo "Building this checkout, and a Debian host to install it on..."
docker build -q -t ares-agent:rehearsal "$REPO_DIR" >/dev/null || { echo "build failed"; exit 1; }
docker build -q -f "$REPO_DIR/Dockerfile.updater" -t ares-updater:rehearsal "$REPO_DIR" >/dev/null
docker save -o "$T/images.tar" ares-agent:rehearsal ares-updater:rehearsal
docker build -q -t "$HOST:image" - >/dev/null <<'EOF'
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      docker.io ca-certificates curl openssl iproute2 procps >/dev/null && \
    rm -rf /var/lib/apt/lists/*
EOF

docker rm -f "$HOST" >/dev/null 2>&1
docker run -d --name "$HOST" --privileged -v "$T:/work" "$HOST:image" \
    sh -c 'dockerd >/var/log/dockerd.log 2>&1' >/dev/null
for _ in $(seq 1 60); do inhost "docker info" >/dev/null 2>&1 && break; sleep 2; done
inhost "docker info" >/dev/null 2>&1 || { echo "inner dockerd never started"; exit 1; }

echo
echo "1. The customer's IT installs their inspection root on the machine"
inhost '
set -e
cd /work
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout CorpRoot.key -out CorpRoot.crt \
  -subj "/O=Example Corp/CN=Example Corp Inspection Root CA" 2>/dev/null
cp CorpRoot.crt /usr/local/share/ca-certificates/CorpRoot.crt
update-ca-certificates >/dev/null 2>&1
' || bad "could not install the root on the host"
if inhost 'openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
      | openssl pkcs7 -print_certs -noout | grep -qi "Example Corp"'; then
    ok "the root is in the host bundle (this is the check to give a customer)"
else
    bad "the root never reached /etc/ssl/certs/ca-certificates.crt"
fi

echo
echo "2. Their network starts inspecting TLS, signing with that same root"
inhost '
set -e
cd /work
docker load -i /work/images.tar >/dev/null
docker pull -q python:3.12-slim >/dev/null
docker pull -q mitmproxy/mitmproxy >/dev/null
docker pull -q curlimages/curl >/dev/null   # pre-pulled so its progress does not litter the run
docker network create --subnet 172.30.0.0/16 corpnet >/dev/null 2>&1 || true
docker run -d --name sim-echo --network corpnet --ip 172.30.0.50 \
  -v /work/echo_server.py:/echo.py:ro python:3.12-slim python /echo.py >/dev/null
docker run -d --name sim-ares --network corpnet -e TARGET_HOST=172.30.0.50 \
  -v /work/fake_ares.py:/fake_ares.py:ro python:3.12-slim \
  sh -c "pip install -q aiohttp && python /fake_ares.py" >/dev/null
mkdir -p /work/mitmconf && cat CorpRoot.key CorpRoot.crt > /work/mitmconf/mitmproxy-ca.pem
chmod 777 /work/mitmconf
docker run -d --name sim-proxy --network corpnet --network-alias ares.assailai.com \
  -v /work/mitmconf:/home/mitmproxy/.mitmproxy \
  mitmproxy/mitmproxy mitmdump --mode reverse:http://sim-ares:8000 --listen-port 443 >/dev/null
echo "$(docker inspect sim-proxy --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}") ares.assailai.com" >> /etc/hosts
' || bad "could not stand up the inspected control plane"
for _ in $(seq 1 60); do
    inhost 'curl -sf --max-time 3 https://ares.assailai.com/result' >/dev/null 2>&1 && break
    sleep 3
done
if inhost 'curl -sf --max-time 10 https://ares.assailai.com/result' >/dev/null 2>&1; then
    ok "the host itself trusts the proxy, so the machine looks perfectly healthy"
else
    bad "the host cannot reach the inspected endpoint at all"
fi

echo
echo "3. Negative control: the previously released agent must still fail here"
inhost "
docker pull -q $PRIOR_RELEASE >/dev/null 2>&1
docker run -d --name old-agent --network host \
  -e ARES_TOKEN=t -e ARES_URL=https://ares.assailai.com -e ARES_NETWORKS=172.30.0.0/16 \
  -v /etc/ssl/certs:/host-ca:ro $PRIOR_RELEASE >/dev/null 2>&1
" || true
sleep 12
case "$(inhost 'docker logs old-agent 2>&1' || true)" in
    *CERTIFICATE_VERIFY_FAILED*)
        ok "$PRIOR_RELEASE fails even WITH the mount, so the bug is reproduced" ;;
    *) bad "the prior release did not fail; this environment is not reproducing the bug" ;;
esac
inhost "docker rm -f old-agent >/dev/null 2>&1" || true

echo
echo "4. The customer runs the install command, with nothing added"
inhost '
cd /work
ARES_TOKEN=ares_agt_rehearsal ARES_URL=https://ares.assailai.com \
ARES_NETWORKS=172.30.0.0/16 ARES_IMAGE=ares-agent:rehearsal \
ARES_UPDATER_IMAGE=ares-updater:rehearsal bash bootstrap.sh >/dev/null 2>&1
' || true
sleep 12
LOG="$(inhost 'docker logs ares-agent 2>&1' || true)"

case "$(inhost 'docker inspect ares-agent --format "{{json .HostConfig.Binds}}"' || true)" in
    *"/etc/ssl/certs:/host-ca:ro"*) ok "bootstrap mounted the host CA store unprompted" ;;
    *) bad "bootstrap did not mount the host CA store" ;;
esac
case "$(inhost 'docker inspect ares-updater --format "{{json .HostConfig.Binds}}"' || true)" in
    *"/etc/ssl/certs:/host-ca:ro"*) ok "and did the same for the updater, so cosign works" ;;
    *) bad "the updater did not get the host CA store" ;;
esac
case "$LOG" in
    *"/host-ca ("*) ok "the agent reports the host CAs it loaded" ;;
    *) bad "the agent loaded no host CAs" ;;
esac
case "$LOG" in
    *"Preflight: control plane OK"*) ok "preflight: control plane" ;;
    *) bad "preflight did not clear the control plane" ;;
esac
case "$LOG" in
    *"Preflight: data-plane tunnel OK"*) ok "preflight: data-plane tunnel" ;;
    *) bad "preflight did not clear the tunnel" ;;
esac
case "$LOG" in
    *"Agent online"*) ok "the agent came online" ;;
    *) bad "the agent never came online" ;;
esac
case "$(inhost 'docker run --rm --network corpnet curlimages/curl -s --max-time 10 \
        http://sim-ares:8000/result' || true)" in
    *'"PASS"'*) ok "a hunt's traffic round-trips byte for byte through the inspected tunnel" ;;
    *) bad "the tunnel did not carry a real stream" ;;
esac

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
