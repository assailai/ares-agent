"""Companion updater: image-ref parsing, target read, the signature gate, and the backends."""

from __future__ import annotations

import json
import re
import types
from pathlib import Path

import httpx
import pytest

from updater import dockerd, kube, main, verify
from updater.config import UpdaterSettings, repo_of, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend


def _settings(**over) -> UpdaterSettings:
    return UpdaterSettings(require_signature=False, **over)


@pytest.fixture(autouse=True)
def _clear_verified_cache():
    # the verified-digest cache is a module global; isolate it between tests.
    main._verified.clear()
    yield


def test_container_name_reads_the_documented_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # the docs / compose / k8s use ARES_UPDATE_CONTAINER; it must actually set container_name
    # (reading only the *_NAME alias was a silent-misconfig bug).
    monkeypatch.setenv("ARES_UPDATE_CONTAINER", "custom-agent")
    assert _settings().container_name == "custom-agent"


def test_image_ref_parsing() -> None:
    assert tag_of("assailai/ares-agent:2.5.0") == "2.5.0"
    assert repo_of("assailai/ares-agent:2.5.0") == "assailai/ares-agent"
    assert tag_of("assailai/ares-agent") == ""  # no tag
    assert repo_of("reg:5000/ares-agent") == "reg:5000/ares-agent"  # the ":" is a registry port
    assert repo_of("assailai/ares-agent@sha256:abc123") == "assailai/ares-agent"  # digest ref
    assert tag_of("assailai/ares-agent@sha256:abc123") == ""  # a digest is not a tag


def test_read_target(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "update-target.json"
    monkeypatch.setattr(main, "settings", _settings(target_file=target))
    assert main._read_target() is None  # not written yet
    target.write_text('{"version": "2.5.0"}')
    assert main._read_target() == "2.5.0"
    target.write_text("not json")  # malformed is ignored, not crashed on
    assert main._read_target() is None


def test_verify_gate() -> None:
    # dev override returns the ref unpinned (with a warning); fail-closed (None) when on but
    # unconfigured (identity + issuer cleared, no key), even though the image now ships a default
    # signer identity.
    assert verify.verify("img:1", UpdaterSettings(require_signature=False)) == "img:1"
    unconfigured = UpdaterSettings(require_signature=True, cosign_identity="", cosign_issuer="")
    assert verify.verify("img:1", unconfigured) is None


def _san(workflow: str, ref: str, repo: str = "assailai/docker-agent-ares") -> str:
    """A GitHub Actions signer identity as Fulcio writes it into the certificate SAN."""
    return f"https://github.com/{repo}/.github/workflows/{workflow}@{ref}"


def test_default_signer_identity_matches_what_ci_actually_signs_with() -> None:
    # a stock updater (no env) verifies signatures out of the box: identity + issuer are baked in,
    # so the docker-run / compose / k8s install commands do not each spell the regexp out.
    # Assert on the regexp's BEHAVIOUR, not its text: a substring check on the repo name let the
    # default drift to a workflow file that never signs anything, and every update failed closed.
    settings = UpdaterSettings()
    assert settings.require_signature is True
    assert settings.cosign_issuer == "https://token.actions.githubusercontent.com"

    identity = re.compile(settings.cosign_identity)
    # the release path (auto-tag.yml -> docker-build.yml) signs at the caller's ref, refs/heads/main;
    # a hand-pushed v* tag signs at the tag ref. Both are ours.
    assert identity.search(_san("docker-build.yml", "refs/heads/main"))
    assert identity.search(_san("docker-build.yml", "refs/tags/v3.3.1"))
    # not ours, or not a signer: another owner/repo, the caller workflow that holds no cosign step,
    # and an unmerged PR build (which does not push or sign at all).
    assert not identity.search(_san("docker-build.yml", "refs/heads/main", repo="attacker/evil"))
    assert not identity.search(_san("docker-publish.yml", "refs/heads/main"))
    assert not identity.search(_san("docker-build.yml", "refs/pull/30/merge"))
    # cosign's -regexp flags are substring matches, so the anchors have to hold on both ends.
    assert not identity.search(_san("docker-build.yml", "refs/heads/main") + ".evil.example")
    assert not identity.search("https://evil.example/" + _san("docker-build.yml", "refs/heads/main"))


def test_default_signer_identity_names_the_workflow_that_signs() -> None:
    # the regexp must name the workflow file containing the `cosign sign` step, because Fulcio takes
    # the certificate SAN from the OIDC job_workflow_ref claim - the file holding the signing job,
    # not the entrypoint workflow that calls it. Deriving the expected file from CI (rather than
    # hardcoding it here) is what catches the signing step moving between workflows again.
    workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    if not workflows.is_dir():
        pytest.skip("no .github/workflows checkout (e.g. running inside the built image)")
    signing = sorted(p.name for p in workflows.glob("*.yml") if "cosign sign" in p.read_text())
    assert signing, "no workflow runs `cosign sign`; the updater's identity regexp is unverifiable"

    identity = re.compile(UpdaterSettings().cosign_identity)
    for workflow in signing:
        assert identity.search(_san(workflow, "refs/heads/main")), (
            f"{workflow} signs images but its identity does not match the updater's regexp"
        )


def test_verify_pins_the_cosign_verified_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    # cosign resolves the tag and attests a digest; verify returns that exact digest pinned to
    # the repo, so the caller applies the verified content rather than re-resolving the tag.
    payload = '[{"critical": {"image": {"docker-manifest-digest": "sha256:abc123"}}}]'
    monkeypatch.setattr(
        verify.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=payload, stderr=""),
    )
    pinned = verify.verify(
        "assailai/ares-agent:3.0.0",
        UpdaterSettings(require_signature=True, cosign_identity="^id$", cosign_issuer="iss"),
    )
    assert pinned == "assailai/ares-agent@sha256:abc123"


def test_docker_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"Config": {"Image": "assailai/ares-agent:2.4.0"}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    assert DockerBackend().running_image(_settings()) == "assailai/ares-agent:2.4.0"


def test_docker_apply_verifies_new_then_swaps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/containers/create":
            return httpx.Response(201, json={"Id": "new123"})
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={"Config": {}, "HostConfig": {}, "State": {"Running": True}})
        return httpx.Response(200, text="")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    monkeypatch.setattr(dockerd, "_client", lambda: client)
    monkeypatch.setattr(dockerd.time, "sleep", lambda _s: None)
    monkeypatch.setattr(dockerd, "_VERIFY_CHECKS", 1)

    DockerBackend().apply(_settings(), "assailai/ares-agent:2.5.0")

    # pulled, created the replacement, started it, then removed the old and renamed the new in.
    assert ("POST", "/images/create") in calls
    assert ("POST", "/containers/create") in calls
    assert ("POST", "/containers/new123/start") in calls
    assert ("DELETE", "/containers/ares-agent") in calls
    assert ("POST", "/containers/new123/rename") in calls


def test_k8s_apply_patches_the_deployment_image(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            seen["body"] = request.read().decode()
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://k8s")
    monkeypatch.setattr(kube, "_client", lambda: client)
    monkeypatch.setattr(kube, "_namespace", lambda _s: "default")

    K8sBackend().apply(_settings(), "assailai/ares-agent:2.5.0")
    container = json.loads(seen["body"])["spec"]["template"]["spec"]["containers"][0]
    assert container == {"name": "ares-agent", "image": "assailai/ares-agent:2.5.0"}


class _FakeBackend:
    """Stand-in backend that records what it was asked to apply."""

    def __init__(self, running: str | None) -> None:
        self.running = running
        self.applied: str | None = None

    def available(self) -> bool:
        return True

    def running_image(self, settings: UpdaterSettings) -> str | None:
        return self.running

    def apply(self, settings: UpdaterSettings, image_ref: str) -> None:
        self.applied = image_ref


def test_tick_derives_repo_from_the_running_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())  # image_repo unset -> derive
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == "assailai/ares-agent:2.5.0"


def test_tick_noop_when_already_on_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "settings", _settings())
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    backend = _FakeBackend(running="assailai/ares-agent:2.5.0")
    main._tick(backend)
    assert backend.applied is None


def test_tick_applies_the_verified_digest_then_noops(monkeypatch: pytest.MonkeyPatch) -> None:
    # the tick applies the DIGEST verify returned (not the tag), closing the TOCTOU; once the
    # agent runs that digest, the cache makes a re-tick a noop (no churn, no re-verify).
    monkeypatch.setattr(main, "settings", _settings())  # verify is mocked below, so the gate is moot
    monkeypatch.setattr(main, "_read_target", lambda: "2.5.0")
    pinned = "assailai/ares-agent@sha256:abc123"
    monkeypatch.setattr(main.verify, "verify", lambda image, settings: pinned)

    backend = _FakeBackend(running="assailai/ares-agent:2.4.0")
    main._tick(backend)
    assert backend.applied == pinned  # the verified digest, not the 2.5.0 tag

    backend.running, backend.applied = pinned, None  # agent now runs the pinned digest
    main._tick(backend)
    assert backend.applied is None  # cache hit -> no re-apply
