# Baked-in trust anchors

## `directive_pub.b64`
Base64 raw Ed25519 **public** key used by the updater (`agent/updater/directive.py`)
to verify signed update directives from the platform.

This is an authorization/anti-replay anchor — **not** the root of trust for code
(that is the cosign image signature, verified in `agent/updater/imageverify.py`).

### Provisioning
1. Generate a keypair on the platform side:
   ```
   python -m core.update_directive --generate   # in services/hunt-agent-manager
   ```
2. Store the printed **private** seed in Vault/KMS as `ARES_DIRECTIVE_SIGNING_KEY`.
3. Replace the contents of `directive_pub.b64` with the printed **public** key and
   rebuild/sign the agent image.

Until a real key is provisioned, the file contains the `REPLACE_ME...` sentinel
and the updater **fails closed** (refuses all directives).

> Rotation note: v1 ships a single baked-in key. The TUF-style rotatable trust
> bundle (current+next keys, offline root, N-of-M) is the documented fast-follow.
