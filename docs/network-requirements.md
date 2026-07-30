# Ares internal agent: outbound network requirements

Everything the agent needs, in one list. All of it is **outbound only**. No inbound firewall rule of
any kind is required: the agent publishes no listening port, and we never dial into your network.

## The short list

If your proxy or firewall accepts wildcards, these are the destinations, all on **TCP 443**:

```
*.assailai.com
*.ares.assailai.com
assailai.com

docker.io
*.docker.io
docker.com
*.docker.com
*.*.docker.com
*.cloudfront.net

github.com
*.github.com
*.githubusercontent.com

*.sigstore.dev
storage.googleapis.com

pypi.org
*.pythonhosted.org
dl-cdn.alpinelinux.org
podman.io
```

Plus, to your own internal servers (not to the internet):

```
DNS   53/udp + 53/tcp   to your internal resolver
NTP   123/udp           to your internal time source
```

### Three wildcard traps worth checking with your firewall vendor

Most enterprise proxies (Palo Alto, Zscaler, Squid, and others) match `*.example.com` against
**exactly one** label, so it covers `foo.example.com` but not `foo.bar.example.com` and not the bare
`example.com`. If yours behaves that way, the wildcard list above is not sufficient on its own and you
should use the explicit FQDN list in the next section. Specifically:

1. **The Docker layer CDN is two labels deep.** A real image pull redirects to
   `production.cloudfront.docker.com` (and, for some clients and regions,
   `production.cloudflare.docker.com`). Neither is matched by a strict single-label `*.docker.com`.
   This is the single most likely thing to still block a pull after the rest of the list is approved.
2. **Apex domains are not matched by a `*.` wildcard.** `github.com` and `docker.io` are contacted
   directly and must be listed in their own right, not only as `*.github.com` / `*.docker.io`.
3. **Our staging aliases are two labels deep.** Production is `ares.assailai.com`, which a
   single-label `*.assailai.com` does cover, but `sidewinder-staging.ares.assailai.com` is not
   covered. Hence `*.ares.assailai.com` as well.

## The full list, explicit FQDNs

Use this if wildcards are not available, or if the wildcard depth above is a concern. Every host here
was resolved and confirmed live on 2026-07-30.

### Ares control plane

The only destination the agent process itself ever contacts.

| Destination | Port | Purpose |
| --- | --- | --- |
| `ares.assailai.com` | 443/tcp | Registration, heartbeat, task polling and task status over HTTPS (HTTP/2), plus the assessment data tunnel as a WebSocket upgrade on the same host and port |
| `sidewinder.ares.assailai.com` | 443/tcp | Alias for the same load balancer |
| `staging.ares.assailai.com` | 443/tcp | Pre-production control plane, so a test agent needs no second firewall change |
| `sidewinder-staging.ares.assailai.com` | 443/tcp | Alias for the same pre-production load balancer |

### Container image pull

Contacted by the Docker or Podman daemon on the host, not by the agent process.

| Destination | Port | Purpose |
| --- | --- | --- |
| `registry-1.docker.io` | 443/tcp | Manifest and layer requests. **This is the host currently being reset by your firewall** |
| `auth.docker.io` | 443/tcp | Pull token issuance |
| `index.docker.io` | 443/tcp | Registry index |
| `docker.io` | 443/tcp | Short image name resolution |
| `registry.docker.io` | 443/tcp | Registry alias used by some client versions |
| `production.cloudfront.docker.com` | 443/tcp | Layer blob CDN, the target a pull is redirected to today |
| `production.cloudflare.docker.com` | 443/tcp | Layer blob CDN, served to some clients and regions |
| `dseasb33srnrn.cloudfront.net` | 443/tcp | Older layer blob CDN, still served to some client versions |
| `hub.docker.com` | 443/tcp | Docker Hub API, used by some client and tooling paths |

### Install scripts and manifests

| Destination | Port | Purpose |
| --- | --- | --- |
| `raw.githubusercontent.com` | 443/tcp | Fetches our bootstrap installer script and Kubernetes manifest |
| `github.com` | 443/tcp | Release and repository redirects |
| `objects.githubusercontent.com` | 443/tcp | Where GitHub redirects release asset downloads |
| `pkg-containers.githubusercontent.com` | 443/tcp | GitHub-hosted container blobs |
| `codeload.github.com` | 443/tcp | Source archive downloads |
| `api.github.com` | 443/tcp | GitHub API, used by tooling that resolves the current release |

### Update signature verification

The auto-update companion verifies the cryptographic signature of a new image before it will apply it.
Verification is mandatory and fails closed, so if these are blocked the agent simply stays on its
current version rather than updating unverified.

| Destination | Port | Purpose |
| --- | --- | --- |
| `tuf-repo-cdn.sigstore.dev` | 443/tcp | Sigstore trust root |
| `rekor.sigstore.dev` | 443/tcp | Transparency log inclusion proof |
| `fulcio.sigstore.dev` | 443/tcp | Sigstore certificate authority |
| `sigstore-tuf-root.storage.googleapis.com` | 443/tcp | Trust root mirror |
| `storage.googleapis.com` | 443/tcp | Parent host for that mirror |
| `token.actions.githubusercontent.com` | 443/tcp | The OIDC issuer named in the signing certificate |

### Building the image locally

Only needed if you choose to build the container image yourself rather than pull ours.

| Destination | Port | Purpose |
| --- | --- | --- |
| `pypi.org` | 443/tcp | Python package index |
| `files.pythonhosted.org` | 443/tcp | Python package downloads |
| `dl-cdn.alpinelinux.org` | 443/tcp | Base image OS packages |

### Installing or updating the container runtime on the host

| Destination | Port | Purpose |
| --- | --- | --- |
| `download.docker.com` | 443/tcp | Docker packages and apt/yum repository |
| `get.docker.com` | 443/tcp | Docker install script |
| `docs.docker.com` | 443/tcp | Referenced by installer output |
| `podman.io` | 443/tcp | Podman install documentation |
| `deb.debian.org`, `security.debian.org`, `http.kali.org`, `kali.download` | 443/tcp, 80/tcp | Your system package manager, when installing or updating the container runtime |

### Internal destinations

Inside your own network, not to the internet.

| Destination | Port | Purpose |
| --- | --- | --- |
| Your internal DNS resolver | 53/udp, 53/tcp | Resolves our control plane, and resolves assessment targets on the agent's own resolver by design, because those names often exist only on your internal DNS |
| Your internal time source | 123/udp | Clock skew breaks TLS, and surfaces as a confusing certificate error rather than a time error |
| The internal hosts you want assessed | TCP on roughly 100 common service ports for discovery, plus the ports of whatever is assessed | Discovery and assessment traffic. Plain TCP connect only: no raw sockets, no root, and no `NET_ADMIN` capability |

## Notes for your firewall team

- **Allowlist by DNS name, not by IP address.** `ares.assailai.com` is an AWS load balancer with one
  address per availability zone and they rotate without notice (currently `100.60.34.135`,
  `98.94.212.162`, `18.205.12.139`). The Docker and GitHub CDN hosts rotate the same way. An
  IP-based rule will work on the day it is written and break later.
- **No inbound rule is needed at all.** Every connection is outbound from your network. The agent
  publishes no port and we never initiate a connection to it.
- **Port 80 is not needed by the agent.** It appears in this list only against OS package mirrors.
- **Layer 7 paths on the control plane**, if you filter by URL path:
  - `POST /api/v1/agent/register`
  - `POST /api/v1/agent/heartbeat`
  - `GET /api/v1/agent/tasks`
  - `POST /api/v1/agent/tasks/{id}/start`, `/progress`, `/complete`, `/fail`
  - WebSocket upgrade on `/api/v1/agent/tunnel`
- **If you terminate and inspect TLS**, the proxy needs to do two things: negotiate ALPN (our client
  speaks HTTP/2, so either `h2` or a clean downgrade to `http/1.1`), and pass a WebSocket upgrade
  through. The agent will not accept a certificate it cannot validate, and there is no supported
  option to disable that check against a production host. Standard `HTTPS_PROXY` and `NO_PROXY`
  environment variables are honoured by the underlying HTTP client, but we do not test that path, so
  please tell us if you intend to rely on it.
- **What the agent never contacts**, so you do not have to wonder: no telemetry, crash reporting, or
  product analytics endpoint of any kind, no third-party address lookup service, and no license
  server. Its entire dependency set is five Python packages and contains no reporting SDK. The only
  internet host the agent process itself dials is our control plane. Everything else in this list is
  the container runtime pulling an image, or verifying that image's signature.
