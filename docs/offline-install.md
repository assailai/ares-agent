# Ares internal agent: install from a file, no registry access needed

These instructions install the agent on a host that cannot reach Docker Hub. Instead of pulling the
image, you load it from the archive included alongside this file.

> **Producing the bundle (Assail side).** Run [`scripts/bundle-offline.sh`](../scripts/bundle-offline.sh),
> which writes one gzipped image archive per architecture plus `SHA256SUMS` into `dist/`. Send the
> customer the archive matching their `uname -m`, `SHA256SUMS`, this document, and
> [`network-requirements.md`](network-requirements.md). Everything below this note is written for the
> customer; the examples use version `3.3.3` and the `amd64` archive, so adjust both to the release you
> are shipping.

The agent still needs outbound HTTPS on port 443 to `ares.assailai.com`. That is the one network
requirement you cannot work around, because it is how the agent registers and reports. Everything
else in [`network-requirements.md`](network-requirements.md) can wait for your firewall change to be
approved.

## What you received

| File | What it is |
| --- | --- |
| `ares-agent-3.3.3-amd64.tar.gz` | The agent image for Intel and AMD hosts (~29 MB) |
| `ares-agent-3.3.3-arm64.tar.gz` | The agent image for ARM hosts (~29 MB) |
| `SHA256SUMS` | Checksums, so you can confirm nothing changed in transit |
| `network-requirements.md` | The full outbound allowlist, for your security team |

You only need the archive matching your host. Copy both if you are not sure yet.

## Install

### 1. Work out which archive you need

On the target host:

```bash
uname -m
```

`x86_64` means use the **amd64** archive. `aarch64` or `arm64` means use the **arm64** archive.

### 2. Copy the files across

From wherever you received them:

```bash
scp ares-agent-3.3.3-amd64.tar.gz SHA256SUMS user@your-host:~/
```

### 3. Verify the transfer

On the target host:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

You want `OK` next to the archive you copied, and nothing else. `--ignore-missing` skips the
architecture you did not copy without treating it as a failure, and the command exits non-zero if the
file you did copy does not match, so it is safe to use in a script.

**Do not continue if this reports `FAILED`.** That means the archive changed in transit; copy it again.

### 4. Load the image

```bash
gunzip -c ares-agent-3.3.3-amd64.tar.gz | docker load
docker images assailai/ares-agent
```

You should see `assailai/ares-agent   3.3.3`. No registry is contacted at any point in this step.

Using Podman instead of Docker? Every command in this document works with `podman` substituted for
`docker`.

### 5. Get a registration token

In the Ares dashboard: **Settings -> Agents -> Deploy an agent**.

The token is **single use** and expires after 72 hours if unused, so generate a fresh one now rather
than reusing an older one. If a previous install attempt already consumed a token, that token will not
work again.

### 6. Run the agent

```bash
docker run -d --name ares-agent --restart=always \
  --network host \
  -e ARES_TOKEN='<paste-your-token-here>' \
  -e ARES_URL=https://ares.assailai.com \
  -e ARES_AGENT_NAME='Internal' \
  -v ares-agent-data:/data \
  assailai/ares-agent:3.3.3
```

### 7. Confirm it worked

```bash
docker logs -f ares-agent
```

Look for `Agent online`. The agent then appears in the dashboard under **Settings -> Agents**, usually
within about 30 seconds. Press Ctrl-C to stop following the log; the agent keeps running.

## Two things that differ from the dashboard's copy-paste command

**`--network host` is added here, and it matters.** Without it the agent sees only the Docker bridge
network and will report `Scanning networks (scope=supernet16): 172.17.0.0/16`, which is Docker's
internal network rather than your real LAN. It will come online and look healthy while discovering
nothing useful. Check the first few log lines: the network it prints should be your actual subnet.

If host networking is against your policy, leave `--network host` off and tell the agent your subnet
explicitly instead:

```bash
  -e ARES_NETWORKS=172.23.33.0/24 \
```

**There is no `ares-updater` container here.** That companion keeps the agent on the current release
automatically, but it works by pulling from Docker Hub and verifying the new image's signature, so it
cannot do anything useful until your firewall allowlist is in place. Leaving it out avoids a container
that sits there failing. Once the allowlist is approved, use the full command from the dashboard,
which includes it, and upgrades become automatic.

## Upgrading later, while still offline

We send you a new archive. Then:

```bash
gunzip -c ares-agent-3.4.0-amd64.tar.gz | docker load
docker rm -f ares-agent
# re-run the command from step 6, with the new version tag
```

The `ares-agent-data` volume keeps the agent's identity, so **it stays the same agent in the
dashboard**. You do not need a new registration token to upgrade.

## Troubleshooting

| What you see | What it means |
| --- | --- |
| `Registration token rejected (expired or already used)` | The token was already consumed or is older than 72 hours. Generate a fresh one in the dashboard. |
| `Refusing to start` mentioning insecure mode | `ARES_INSECURE` was set. Do not set it against a production URL; the agent rejects it on purpose. Remove it. |
| Logs show `172.17.0.0/16` as the scanned network | `--network host` is missing, or set `ARES_NETWORKS` explicitly. See the section above. |
| Registration times out or the connection is refused | Outbound 443 to `ares.assailai.com` is blocked. Check with `curl -sI https://ares.assailai.com` from the host; you want an HTTP response, not a hang or a reset. |
| Certificate validation errors | Either a TLS-inspecting proxy is in the path (see [`network-requirements.md`](network-requirements.md)), or the host clock is wrong. Check `date`. |
| `Unable to find image ... locally` then a registry error | The image was not loaded, or the tag does not match. Re-run step 4 and check `docker images assailai/ares-agent`. |
| Container keeps restarting | `docker logs ares-agent` will say why. The agent restarts itself deliberately if it cannot reach us for 10 minutes. |
| It comes online, but as an agent you already had, ignoring your new token | The `ares-agent-data` volume already held an identity from a previous install, and the agent keeps its existing one rather than registering again. That is the right behaviour for a restart or an upgrade. If you actually want a **new** enrollment, remove the volume first with `docker volume rm ares-agent-data` (this discards that agent's identity, so only do it if you intend to re-register), or run the new one under a different `--name` and `-v` volume name. |

Useful commands:

```bash
docker logs -f ares-agent      # follow the log
docker restart ares-agent      # restart it
docker rm -f ares-agent        # remove it; the data volume and its identity are kept
```

## What the agent does on your host

Worth knowing before you deploy it, and covered in more detail in [`network-requirements.md`](network-requirements.md):

- It runs as a **non-root** user and needs no added Linux capabilities, no `NET_ADMIN`, and no TUN
  device.
- It **listens on no port**. Every connection is outbound from your network, and we never dial in.
- It **downloads nothing at runtime**. The image is self-contained, which is why this offline install
  works at all.
- It sends no telemetry or analytics anywhere. The only internet host it contacts is
  `ares.assailai.com`.
- Its only writable state is the `ares-agent-data` volume, holding its own identity and status.
