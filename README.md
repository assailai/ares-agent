# Ares Agent

[![Docker Image Version](https://img.shields.io/docker/v/assailai/ares-agent?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/assailai/ares-agent)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

Customer-deployable Docker agent that lets the [Ares](https://www.assailai.com) platform hunt
internal services that aren't exposed to the internet. Deploy it inside your network with one
command: it registers itself, shows up in your dashboard, scans the internal ranges you approve,
and gives Ares a way to reach the discovered hosts for assessment.

The agent is **outbound-only and headless**. There is no web UI, no inbound port to open, and no
host privileges to grant.

## How it works

```
  Your internal network                              Ares platform (cloud)
 ┌───────────────────────────┐                      ┌──────────────────────────┐
 │  ares-agent (container)    │   HTTPS (443)        │  control plane           │
 │   1. read ARES_TOKEN       │ ───────────────────▶ │   register / heartbeat   │
 │   2. auto-detect LAN CIDRs │                      │   poll tasks / report    │
 │   3. connect-scan locally  │   WebSocket (443)    │                          │
 │   4. proxy to internal     │ ◀═══════════════════▶ │  hunt assessment         │
 │      hosts during a hunt   │   (opened on demand) │                          │
 └───────────────────────────┘                      └──────────────────────────┘
```

1. **Register** - on start the agent reads its one-time registration token, auto-detects the
   internal networks it can see, and registers over HTTPS. It then appears in your dashboard.
2. **Heartbeat + poll** - it checks in on a fixed cadence and polls for scan tasks. No inbound
   connections are ever made to the agent.
3. **Scan** - when you launch an internal hunt, the agent runs a TCP-connect scan of the
   approved CIDRs and reports the live hosts it found.
4. **Reach-in** - while a hunt is running the agent opens an outbound WebSocket back to Ares and
   proxies TCP streams to the destination being assessed. The tunnel is closed when no hunt is
   active. Two kinds of destination are allowed, and the agent decides:
   - an **IP address** must be inside the networks you approved for this agent;
   - a **hostname** is resolved by *this host*, on your own DNS, which is how Ares assesses a URL
     that only exists inside your network. It is allowed when every address it resolves to is
     inside your approved networks, or when it is the target of an assessment you launched in
     Ares (Ares names that host on the heartbeat, and only while the run is live). The agent then
     connects to the address it checked, so a second lookup cannot redirect the connection.

## Getting started

**Get your install command from the Ares platform, not by hand.** In Ares, open
**Settings -> Agents -> Deploy an agent**. It generates a ready-to-run command with your one-time
registration token, the correct control-plane URL for your environment, and the agent name already
filled in. Copy that command and run it on the host you want to deploy on; that is the whole setup.
The token is single-use (one agent per token), and the dashboard pins the current release version
for you.

The options below just show the *shape* of what the dashboard hands you (each needs the
`ARES_TOKEN` it issues), in case you want to adapt it for Compose, Kubernetes, or your own tooling.

### Option A: Docker run

The dashboard's Deploy flow gives you exactly this command, filled in. Pin to a specific version
(the deploy command shows the current release); avoid `:latest` so deploys are reproducible.

```bash
docker run -d --name ares-agent \
  -e ARES_TOKEN=<your-registration-token> \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  assailai/ares-agent:<version>
```

Watch it enroll and come online:

```bash
docker logs -f ares-agent
# ... Registered as agent <id>
# ... Agent online, visible in the dashboard as "<name>".
```

Images are published to Docker Hub: `assailai/ares-agent` and `assailai/ares-updater` (the companion updater), tagged per release.

### Option B: Docker Compose

```bash
ARES_TOKEN=<your-registration-token> docker compose up -d
docker compose logs -f
```

See [docker-compose.yml](docker-compose.yml) for the full configuration.

### Option C: Bootstrap script

The bootstrap script checks Docker is available, starts the container, and waits until the agent
reports online:

```bash
ARES_TOKEN=<your-registration-token> bash <(curl -fsSL https://raw.githubusercontent.com/assailai/ares-agent/main/scripts/bootstrap.sh)
```

It also accepts the token as an argument or prompts for it interactively. Works on macOS, Linux,
and Windows (Git Bash / WSL).

### Option D: Kubernetes

Apply the bundled manifest, [`deploy/k8s/ares-agent.yaml`](deploy/k8s/ares-agent.yaml). It is the
canonical, auto-updating deployment and bundles everything the agent needs on k8s:

- the agent plus the companion `ares-updater` **sidecar** (a ServiceAccount scoped to patch only
  this Deployment, so a dashboard "Update" triggers a native rolling update),
- a PVC for the agent's state, and
- `securityContext.fsGroup: 10001` so the non-root agent (uid/gid 10001) can write that volume.
  Without it the agent cannot persist its identity, the liveness check fails, and the pod
  crash-loops (a PVC mounts root-owned, unlike a Docker volume).

The `assailai/ares-agent` and `assailai/ares-updater` images are public on Docker Hub, so no
image pull secret is required.

```bash
curl -fsSLO https://raw.githubusercontent.com/assailai/ares-agent/main/deploy/k8s/ares-agent.yaml
# set ARES_TOKEN in the Secret at the top of the file (and pin the image to a release), then:
kubectl apply -f ares-agent.yaml
kubectl rollout status deploy/ares-agent
```

To opt out of auto-update, delete the `ares-updater` container plus its ServiceAccount, Role, and
RoleBinding, and update the image through your own pipeline instead.

## Configuration

The agent is configured entirely through environment variables (all prefixed `ARES_`).

| Variable | Default | Description |
|----------|---------|-------------|
| `ARES_TOKEN` | *(required)* | One-time registration token from the dashboard. The agent exits with a clear message if it is missing. |
| `ARES_URL` | `https://api.assailai.com` | Base URL of the Ares control plane. Override when self-hosting. |
| `ARES_NETWORKS` | *(auto-detected)* | Comma-separated CIDRs to scan, e.g. `10.0.0.0/24,192.168.1.0/24`. Overrides auto-detection. You can also edit the networks in the dashboard after enrollment. |
| `ARES_AGENT_NAME` | *(host name)* | Friendly name shown in the dashboard. |
| `ARES_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `ARES_INSECURE` | `false` | Skip TLS verification. Local and staging URLs only; the agent refuses to start with this set against a production URL. |

### Volume

| Path | Description |
|------|-------------|
| `/data` | Persistent state. Holds `agent-state.json` (the agent id and its auth token) so the agent keeps its identity across restarts. |

## Network requirements

The agent only makes **outbound** connections, all to your Ares URL:

| Direction | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Outbound | 443 | HTTPS | Registration, heartbeat, task polling, result reporting |
| Outbound | 443 | WebSocket (WSS) | Data-plane tunnel, opened only while a hunt is running |

**No inbound firewall rules are required.** Locally, the agent connects to the internal hosts on
whatever ports your hunt targets (commonly 80, 443, 8080, 8443).

## Security

- **Non-root, no privileges** - the container runs as an unprivileged user (uid 10001). It needs
  no `NET_ADMIN`, no `/dev/net/tun`, and no host `sysctl` changes.
- **Outbound-only** - the agent initiates every connection. Nothing listens for inbound traffic.
- **Scoped reach-in** - the data-plane tunnel only proxies to the networks you approved for the
  agent, or to the hostname of a target you explicitly approved and launched in Ares, enforced on
  the agent side. It exists only while a hunt is running. Names are resolved here, never in the
  cloud, and every refusal is logged with its reason.
- **Minimal image** - multi-stage Alpine build with runtime dependencies only; no secrets baked
  into the image.
- **Token at rest** - the agent's auth token lives in the `/data` volume (mode 0700), supplied at
  runtime and never in the image.

## Upgrading

Pin the agent to a specific version (the current release is shown in the Ares dashboard under
Settings -> Agents) rather than a moving tag, so deploys are reproducible. The `/data` volume
holds the agent's identity, so an upgrade is a pull and re-create on the new tag:

```bash
docker rm -f ares-agent
docker pull assailai/ares-agent:<new-version>
# re-run the docker run command from Getting started with the new tag (the volume is reused)
```

Or with Compose: bump the pinned `image:` tag, then `docker compose pull && docker compose up -d`.

### Auto-update (the companion updater)

The deployment bundles a small `ares-updater` companion that keeps the agent on the version you
mark current in the dashboard. The **agent stays unprivileged**; only the updater holds the
platform access, verifies the target image's signature, and applies it:

- **Docker Compose** (`docker-compose.yml`): the `ares-updater` service holds the Docker socket
  and recreates the agent container on the new version, verify-then-swap (the replacement is
  confirmed up before the old container is removed, so a bad version never takes the agent down).
- **Kubernetes** (`deploy/k8s/ares-agent.yaml`): the updater runs as a sidecar with a
  ServiceAccount scoped to patch only the agent Deployment, triggering a native rolling update.

Notes:

- The agent moves to the exact version the dashboard marks current (a pinned tag), so rollouts
  are deterministic and promotable across environments.
- Verification is **fail-closed** (`ARES_UPDATE_REQUIRE_SIGNATURE=true`): the updater refuses an
  image it cannot cosign-verify. Set it `false` only for local/dev, before image signing is wired.
- Only the updater touches the runtime (the Docker socket, or the scoped k8s RBAC); the agent has
  neither. To disable auto-update, remove the updater service/sidecar and update the image
  yourself (`docker compose pull && docker compose up -d`, or your GitOps pipeline).

## Troubleshooting

Start with the logs: `docker logs ares-agent`. The agent narrates each step.

| Symptom in the logs | Cause and fix |
|---------------------|---------------|
| `ARES_TOKEN is required` | No token was passed. Add `-e ARES_TOKEN=...`. |
| `Registration token rejected` | The token expired or was already used. Generate a fresh one in Settings -> Agents. |
| `Cannot reach Ares at ...` | The host can't reach your Ares URL on 443. Check egress / proxy rules. The agent keeps retrying. |
| `No internal LAN auto-detected` | Auto-detection found nothing scannable. Set `ARES_NETWORKS=10.0.0.0/24,...` or edit the networks in the dashboard. |
| `Heartbeat unauthorized` | The stored agent credentials were rejected (a decommissioned agent, or stale credentials from a kept `/data` volume). After a few consecutive rejections the agent tries to re-enroll with `ARES_TOKEN`: if the token is still unused it adopts a fresh identity and recovers; if the token is spent it keeps the current credentials and retries (it does not exit or wipe anything), so a decommissioned agent idles quietly. To give such an agent a new identity, redeploy with a fresh token. |

**Health check.** The container is healthy once it has registered, which is when
`/data/agent-state.json` exists:

```bash
docker exec ares-agent test -f /data/agent-state.json && echo "registered"
```

**Complete reset** (you'll need a new registration token):

```bash
docker rm -f ares-agent
docker volume rm ares-agent-data
```

## Versioning

We use [Semantic Versioning](https://semver.org/). For available versions, see the
[tags on Docker Hub](https://hub.docker.com/r/assailai/ares-agent/tags).

## Support

- **Documentation**: [https://www.assailai.com](https://www.assailai.com)
- **Email**: support@assailai.com
- **Issues**: [GitHub Issues](https://github.com/assailai/ares-agent/issues)

If you discover a security vulnerability, please email security@assailai.com instead of opening a
public issue.

## License

This software is proprietary and provided under the [Assail, Inc. Terms of Service](https://www.assailai.com/terms).
Use of this agent requires an active Ares subscription. See [LICENSE](LICENSE) for details.

---

Copyright 2025 Assail, Inc. All rights reserved.
