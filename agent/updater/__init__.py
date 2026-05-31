"""Ares Docker Agent — self-update sidecar.

Runs as a SEPARATE container from the long-running agent (same image,
``ARES_ROLE=updater``) so the network-exposed agent process never holds the
Docker socket. The updater:

  1. polls the platform for a SIGNED update directive (anti-replay via a fresh
     client nonce it generates each request),
  2. verifies the directive's Ed25519 signature against a public key baked into
     this image,
  3. cosign-verifies the target image digest against the release workflow's
     keyless identity (the ROOT of trust for code),
  4. pulls the image BY DIGEST and confirms the local digest matches,
  5. recreates the agent container from a FIXED recipe (no value from the
     directive influences caps/mounts/env),
  6. health-checks the new container, atomically swaps, and rolls back on any
     failure — with a per-digest circuit breaker, a single-update lock, and a
     free-disk guard.

See ``agent/updater/runner.py`` for the orchestration and the threat-model notes.
"""
