# Ares Agent

[![Docker Image Version](https://img.shields.io/docker/v/assailai/ares-agent?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/assailai/ares-agent)
[![GitHub Container Registry](https://img.shields.io/badge/ghcr.io-available-blue)](https://github.com/assailai/ares-agent/pkgs/container/ares-agent)
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
   proxies TCP streams to the discovered hosts, restricted to the networks you approved. The
   tunnel is closed when no hunt is active.

## Getting started

You need a **registration token** first. In the Ares dashboard go to **Settings -> Agents**,
generate a token (it starts with `ares_agt_`), and copy it. Tokens are one-time: each enrolls a
single agent.

### Option A: Docker run

```bash
docker run -d --name ares-agent \
  --platform linux/amd64 \
  -e ARES_TOKEN=<your-registration-token> \
  -v ares-agent-data:/data \
  --restart unless-stopped \
  ghcr.io/assailai/ares-agent:latest
```

Watch it enroll and come online:

```bash
docker logs -f ares-agent
# ... Registered as agent <id>
# ... Agent online, visible in the dashboard as "<name>".
```

The image is also published on Docker Hub as `assailai/ares-agent:latest`.

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

The agent needs no special capabilities, so the manifest is a plain Deployment plus a volume for
its state. Put the token in a Secret rather than inline.

<details>
<summary>Click to expand Kubernetes manifests</summary>

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ares-agent
stringData:
  ARES_TOKEN: "<your-registration-token>"
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ares-agent-pvc
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ares-agent
  labels:
    app: ares-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ares-agent
  template:
    metadata:
      labels:
        app: ares-agent
    spec:
      containers:
      - name: ares-agent
        image: ghcr.io/assailai/ares-agent:latest
        envFrom:
        - secretRef:
            name: ares-agent
        volumeMounts:
        - name: data
          mountPath: /data
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "250m"
        livenessProbe:
          exec:
            command: ["test", "-f", "/data/agent-state.json"]
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: ares-agent-pvc
```

</details>

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
  agent, enforced on the agent side. It exists only while a hunt is running.
- **Minimal image** - multi-stage Alpine build with runtime dependencies only; no secrets baked
  into the image.
- **Token at rest** - the agent's auth token lives in the `/data` volume (mode 0700), supplied at
  runtime and never in the image.

## Upgrading

The `/data` volume holds the agent's identity, so an upgrade is a pull and re-create:

```bash
docker rm -f ares-agent
docker pull ghcr.io/assailai/ares-agent:latest
# re-run the docker run command from Getting started (the volume is reused)
```

Or with Compose: `docker compose pull && docker compose up -d`.

### Self-update (optional)

By default upgrades are manual (above): the dashboard surfaces version drift and you redeploy. If
you want a dashboard "Update" to apply itself, opt in with `ARES_SELF_UPDATE=true` and mount the
Docker socket:

```bash
docker run -d --name ares-agent \
  --platform linux/amd64 \
  -e ARES_TOKEN=<your-registration-token> \
  -e ARES_SELF_UPDATE=true \
  -v ares-agent-data:/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --restart unless-stopped \
  ghcr.io/assailai/ares-agent:latest
```

When the dashboard queues an update, the agent launches a one-shot
[Watchtower](https://containrrr.dev/watchtower/) that pulls the image and recreates this container
with the same configuration. Notes:

- **The Docker socket grants host-level access.** Only enable self-update if that tradeoff is
  acceptable on the host.
- Self-update tracks the **running image tag**, so keep the agent on a moving tag like `:latest`
  for new releases to be picked up.
- **Kubernetes:** do not use this; update the Deployment image instead (`kubectl set image` or your
  GitOps pipeline).

## Troubleshooting

Start with the logs: `docker logs ares-agent`. The agent narrates each step.

| Symptom in the logs | Cause and fix |
|---------------------|---------------|
| `ARES_TOKEN is required` | No token was passed. Add `-e ARES_TOKEN=...`. |
| `Registration token rejected` | The token expired or was already used. Generate a fresh one in Settings -> Agents. |
| `Cannot reach Ares at ...` | The host can't reach your Ares URL on 443. Check egress / proxy rules. The agent keeps retrying. |
| `No internal LAN auto-detected` | Auto-detection found nothing scannable. Set `ARES_NETWORKS=10.0.0.0/24,...` or edit the networks in the dashboard. |
| `Heartbeat unauthorized` | The agent was decommissioned in the dashboard. Re-enroll with a new token. |

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
