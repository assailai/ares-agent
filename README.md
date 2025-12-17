# Ares Agent

[![Docker Image Version](https://img.shields.io/docker/v/assailai/ares-agent?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/assailai/ares-agent)
[![GitHub Container Registry](https://img.shields.io/badge/ghcr.io-available-blue)](https://github.com/assailai/ares-agent/pkgs/container/ares-agent)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/Security-Hardened-green.svg)](#security)

Customer-deployable Docker agent for scanning internal APIs through the [Ares](https://assail.ai) platform. Deploy this agent inside your network to enable secure API security testing of internal services that aren't exposed to the internet.

## Overview

The Ares Agent establishes a secure WireGuard VPN tunnel from your internal network to the Ares platform, allowing Ares to perform comprehensive API security testing on your internal services without requiring inbound firewall rules or exposing your APIs to the internet.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Your Internal Network                         │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐  │
│  │ Internal    │      │   Ares      │      │  Internal APIs      │  │
│  │ Services    │◄────►│   Agent     │◄────►│  (10.x.x.x)         │  │
│  └─────────────┘      └──────┬──────┘      └─────────────────────┘  │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │ WireGuard VPN (Outbound UDP 51820)
                               │ ChaCha20-Poly1305 Encryption
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Ares Cloud Platform                          │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐  │
│  │ API Security│      │   Tunnel    │      │  Results &          │  │
│  │ Scanner     │◄────►│   Gateway   │◄────►│  Dashboard          │  │
│  └─────────────┘      └─────────────┘      └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

- **Web-Based Setup Wizard** - Intuitive browser-based configuration with step-by-step guidance
- **Secure by Default** - Non-root execution, TLS encryption, bcrypt password hashing, session management
- **Encryption at Rest** - Sensitive data (keys, tokens) encrypted using Fernet (AES-128-CBC + HMAC)
- **WireGuard VPN Tunnel** - Industry-standard encrypted tunnel using ChaCha20-Poly1305
- **No Inbound Firewall Rules** - Agent initiates all connections; no ports need to be opened inbound
- **Persistent Configuration** - Settings survive container restarts via Docker volumes
- **Health Monitoring** - Built-in health checks for container orchestration
- **Audit Logging** - All administrative actions logged locally

## Quick Start

### Pull and Run

```bash
# Using Docker Hub
docker run -d \
  --name ares-agent \
  --user root \
  --privileged \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  -v /lib/modules:/lib/modules:ro \
  --device /dev/net/tun:/dev/net/tun \
  -e ARES_RUN_AS_ROOT=true \
  assailai/ares-agent:latest

# Or using GitHub Container Registry
docker run -d \
  --name ares-agent \
  --user root \
  --privileged \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  -v /lib/modules:/lib/modules:ro \
  --device /dev/net/tun:/dev/net/tun \
  -e ARES_RUN_AS_ROOT=true \
  ghcr.io/assailai/ares-agent:latest
```

> **Note:** The `--privileged` flag and `--user root` are required for WireGuard VPN to function properly. The `ARES_RUN_AS_ROOT=true` environment variable prevents privilege dropping so WireGuard can manage network interfaces.

### Get Initial Password

```bash
docker logs ares-agent
```

You'll see output like:

```
╔══════════════════════════════════════════════════════════════════════╗
║                    ARES DOCKER AGENT v1.1.0                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Web Interface:  https://192.168.1.50:8443                           ║
║  Initial Password:  xK9#mP2$vL5@nQ8                                  ║
║                                                                      ║
║  NOTE: You MUST change this password on first login.                 ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Access Web Interface

1. Navigate to `https://<your-host>:8443` in your browser
2. Accept the self-signed certificate warning
3. Log in with the initial password from the logs
4. Complete the setup wizard

## Requirements

| Requirement | Details |
|-------------|---------|
| **Docker** | Version 20.10 or later |
| **Privileges** | `--privileged` and `--user root` (required for WireGuard VPN) |
| **TUN Device** | `--device /dev/net/tun:/dev/net/tun` |
| **Kernel Modules** | `-v /lib/modules:/lib/modules:ro` (for WireGuard kernel module) |
| **Outbound UDP** | Port 51820 to Ares platform (WireGuard) |
| **Outbound TCP** | Port 443 to Ares platform (Registration) |
| **Memory** | Minimum 256MB |
| **Disk** | Minimum 100MB for data volume |

## Installation

### Docker Run

```bash
docker run -d \
  --name ares-agent \
  --user root \
  --privileged \
  -p 8443:8443 \
  -v ares-agent-data:/data \
  -v /lib/modules:/lib/modules:ro \
  --device /dev/net/tun:/dev/net/tun \
  -e ARES_RUN_AS_ROOT=true \
  --restart unless-stopped \
  assailai/ares-agent:latest
```

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  ares-agent:
    image: assailai/ares-agent:latest
    container_name: ares-agent
    user: root
    privileged: true
    ports:
      - "8443:8443"
    volumes:
      - ares-agent-data:/data
      - /lib/modules:/lib/modules:ro
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      - ARES_RUN_AS_ROOT=true
    sysctls:
      - net.ipv4.ip_forward=1
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "--no-check-certificate", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

volumes:
  ares-agent-data:
```

Then run:

```bash
docker-compose up -d
```

### Kubernetes

```yaml
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
        image: assailai/ares-agent:latest
        ports:
        - containerPort: 8443
          name: https
        env:
        - name: ARES_RUN_AS_ROOT
          value: "true"
        volumeMounts:
        - name: data
          mountPath: /data
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        securityContext:
          privileged: true
          runAsUser: 0
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: ares-agent-pvc
      - name: lib-modules
        hostPath:
          path: /lib/modules
          type: Directory
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ares-agent-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: ares-agent
spec:
  selector:
    app: ares-agent
  ports:
  - port: 8443
    targetPort: 8443
    name: https
  type: ClusterIP
```

## Configuration

### Setup Wizard Steps

1. **Login** - Use the initial password from container logs
2. **Change Password** - Set a strong password (minimum 12 characters)
3. **Platform URL** - Enter your Ares platform URL (e.g., `https://api.assail.ai`)
4. **Registration Token** - Generate a token from the Ares dashboard and enter it here
5. **Internal Networks** - Define which CIDR ranges can be scanned (e.g., `10.0.0.0/8`, `172.16.0.0/12`)
6. **Agent Name** - Give your agent a descriptive name for the dashboard
7. **Connect** - Establish the WireGuard tunnel

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ARES_RUN_AS_ROOT` | `false` | Set to `true` to keep running as root (required for WireGuard) |
| `DATA_DIR` | `/data` | Directory for persistent data |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `HTTPS_PORT` | `8443` | Port for web interface |

### Volumes

| Path | Description |
|------|-------------|
| `/data` | All persistent data (config, database, certificates) |
| `/data/tls` | TLS certificates for web interface |
| `/data/wireguard` | WireGuard VPN configuration |
| `/data/db` | SQLite database |

### Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 8443 | TCP | Web interface (HTTPS) |

## Network Requirements

### Outbound (Required)

| Destination | Port | Protocol | Description |
|-------------|------|----------|-------------|
| Ares Platform | 51820 | UDP | WireGuard VPN tunnel |
| Ares Platform | 443 | TCP | Initial registration and API |

### Inbound

**No inbound firewall rules required.** The agent initiates all connections outbound.

## Security

The Ares Agent is built with security as a top priority:

### Container Security
- **Privileged mode required** - WireGuard VPN requires root and privileged mode for kernel module access
- **Minimal attack surface** - Multi-stage build with only runtime dependencies
- **No secrets in image** - All credentials provided at runtime
- **Isolated networking** - WireGuard creates an isolated overlay network

### Authentication & Sessions
- **bcrypt password hashing** - Cost factor 12
- **Secure sessions** - 24-hour expiry, HttpOnly, SameSite=Strict cookies
- **Account lockout** - 5 failed attempts triggers 30-minute lockout
- **Forced password change** - Initial password must be changed on first login

### Data Protection
- **Encryption at rest** - Sensitive data encrypted using Fernet (AES-128-CBC + HMAC)
- **Key derivation** - HKDF with unique contexts per data type
- **Protected fields** - WireGuard private keys, JWT tokens, registration tokens
- **Secure key storage** - Master encryption key stored with 0600 permissions

### Network Security
- **TLS 1.2+** - Self-signed certificate auto-generated on first run
- **WireGuard VPN** - ChaCha20-Poly1305 authenticated encryption
- **No inbound ports** - Agent initiates all connections

### Audit & Compliance
- **Audit logging** - All administrative actions logged with timestamps
- **Docker Scout compliant** - Passes Docker security scanning
- **CVE monitoring** - Dependencies pinned to versions with known CVE fixes

## Troubleshooting

### Container Won't Start

**Symptom:** Container exits immediately

**Solution:** Ensure all required flags are provided:
```bash
docker run --user root --privileged --device /dev/net/tun:/dev/net/tun -e ARES_RUN_AS_ROOT=true ...
```

### Can't Access Web Interface

**Checklist:**
1. Verify container is running: `docker ps | grep ares-agent`
2. Check container logs: `docker logs ares-agent`
3. Verify port mapping: `docker port ares-agent`
4. Test local access from host: `curl -k https://localhost:8443/health`

### WireGuard Tunnel Not Connecting

**Checklist:**
1. Verify outbound UDP 51820 is allowed by your firewall
2. Check registration token hasn't expired (24-hour validity)
3. Verify platform URL is correct
4. Check agent logs in web interface (Dashboard > Logs)

### Forgot Password

Reset by removing the data volume:
```bash
docker stop ares-agent
docker rm ares-agent
docker volume rm ares-agent-data
# Re-run the container to get a new initial password
```

### Health Check Failing

View detailed health status:
```bash
docker exec ares-agent wget -qO- --no-check-certificate https://localhost:8443/health
```

## Versioning

We use [Semantic Versioning](https://semver.org/). For available versions, see the [tags on Docker Hub](https://hub.docker.com/r/assailai/ares-agent/tags).

| Version | Status | Notes |
|---------|--------|-------|
| 1.1.x | Current | WireGuard fixes, requires privileged mode |
| 1.0.x | Legacy | May have WireGuard connectivity issues |

## Support

- **Documentation**: [https://docs.assail.ai](https://docs.assail.ai)
- **Email**: support@assail.ai
- **Issues**: [GitHub Issues](https://github.com/assailai/ares-agent/issues)

### Reporting Security Vulnerabilities

If you discover a security vulnerability, please email security@assail.ai instead of opening a public issue. We take security seriously and will respond promptly.

## License

This software is proprietary and provided under the [Assail AI Terms of Service](https://assail.ai/terms). Use of this agent requires an active Ares subscription.

See [LICENSE](LICENSE) for details.

---

Copyright 2025 Assail AI. All rights reserved.
