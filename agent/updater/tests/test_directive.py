"""Tests for the update-directive verifier — the authorization/anti-replay gate.

Run: python -m unittest agent.updater.tests.test_directive
Only requires `cryptography` (already a runtime dep).
"""
import base64
import json
import os
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NONCE = "n" * 32
AGENT_ID = "agent-123"
CURRENT = "2.4.0"
REGISTRY = "ghcr.io/assailai/docker-agent-ares"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class DirectiveVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = Ed25519PrivateKey.generate()
        pub = cls.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        os.environ["ARES_DIRECTIVE_PUBKEY_B64"] = base64.b64encode(pub).decode()
        os.environ["ARES_AGENT_REGISTRY"] = REGISTRY

    def _sign(self, payload: dict) -> dict:
        sig = self.key.sign(_canonical(payload))
        return {"payload": payload, "signature": base64.b64encode(sig).decode(), "alg": "ed25519"}

    def _good_payload(self) -> dict:
        return {
            "client_nonce": NONCE,
            "agent_id": AGENT_ID,
            "tenant_id": "t1",
            "target_version": "2.5.0",
            "target_digest": "sha256:" + ("a" * 64),
            "registry": REGISTRY,
            "min_acceptable_version": "2.4.0",
            "revoked_digests": [],
            "issued_at": "now",
        }

    def _verify(self, signed, **overrides):
        from agent.updater.directive import verify_directive

        kw = dict(client_nonce=NONCE, agent_id=AGENT_ID, current_version=CURRENT)
        kw.update(overrides)
        return verify_directive(signed, **kw)

    def test_happy_path(self):
        p = self._verify(self._sign(self._good_payload()))
        self.assertEqual(p["target_version"], "2.5.0")

    def test_rejects_replayed_nonce(self):
        from agent.updater.directive import DirectiveError

        with self.assertRaises(DirectiveError):
            self._verify(self._sign(self._good_payload()), client_nonce="different" * 4)

    def test_rejects_wrong_agent(self):
        from agent.updater.directive import DirectiveError

        with self.assertRaises(DirectiveError):
            self._verify(self._sign(self._good_payload()), agent_id="someone-else")

    def test_rejects_downgrade(self):
        from agent.updater.directive import DirectiveError

        p = self._good_payload()
        p["target_version"] = "2.3.0"
        with self.assertRaises(DirectiveError):
            self._verify(self._sign(p))

    def test_rejects_wrong_registry(self):
        from agent.updater.directive import DirectiveError

        p = self._good_payload()
        p["registry"] = "evil.example/x"
        with self.assertRaises(DirectiveError):
            self._verify(self._sign(p))

    def test_rejects_revoked_digest(self):
        from agent.updater.directive import DirectiveError

        p = self._good_payload()
        p["revoked_digests"] = [p["target_digest"]]
        with self.assertRaises(DirectiveError):
            self._verify(self._sign(p))

    def test_rejects_tampered_payload(self):
        from agent.updater.directive import DirectiveError

        signed = self._sign(self._good_payload())
        tampered = dict(signed["payload"])
        tampered["target_digest"] = "sha256:" + ("e" * 64)
        signed["payload"] = tampered  # signature no longer matches
        with self.assertRaises(DirectiveError):
            self._verify(signed)

    def test_rejects_below_floor(self):
        from agent.updater.directive import DirectiveError

        p = self._good_payload()
        p["min_acceptable_version"] = "3.0.0"  # target 2.5.0 < floor
        with self.assertRaises(DirectiveError):
            self._verify(self._sign(p))


if __name__ == "__main__":
    unittest.main()
