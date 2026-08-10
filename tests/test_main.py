"""Control-plane loop resilience: failure logging is visible but never spammy, the
agent only claims to be online once a beat is accepted, and a sustained authorization
failure re-enrolls (non-destructively) instead of 401-looping forever or stranding a
healthy agent on a spent one-time token."""

from __future__ import annotations

import asyncio
import logging
import time
from unittest.mock import Mock

import httpx
import pytest
from pydantic import SecretStr

from agent import main
from agent.state import AgentState


def test_repeated_failure_logging_escalates_then_quiets(caplog: pytest.LogCaptureFixture) -> None:
    # the first failure and every tenth are WARNING (visible at the default INFO level) so a
    # sustained outage is never silent; the noisy middle stays DEBUG so a flaky minute does not
    # flood the log.
    exc = RuntimeError("boom")
    with caplog.at_level(logging.DEBUG, logger="ares.agent"):
        _log_repeated_failure = main._log_repeated_failure
        _log_repeated_failure("heartbeat", 1, exc)
        _log_repeated_failure("heartbeat", 5, exc)
        _log_repeated_failure("heartbeat", 10, exc)

    by_message = {record.getMessage(): record.levelno for record in caplog.records}
    assert by_message["heartbeat failing (attempt 1): boom"] == logging.WARNING
    assert by_message["heartbeat failed (attempt 5): boom"] == logging.DEBUG
    assert by_message["heartbeat failing (attempt 10): boom"] == logging.WARNING


def _unauthorized() -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://ares.example/api/v1/agent/heartbeat")
    response = httpx.Response(401, request=request)
    return httpx.HTTPStatusError("401", request=request, response=response)


@pytest.fixture
def _instant_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip the real delays / sampling out of the heartbeat loop so it iterates instantly."""
    monkeypatch.setattr(main, "read_cpu_percent", lambda: 0.0)
    monkeypatch.setattr(main, "read_memory_percent", lambda: 0.0)

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)


@pytest.mark.usefixtures("_instant_loop")
async def test_heartbeat_reenrolls_after_sustained_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every beat is rejected: after the threshold the loop raises _AuthInvalidated so run()
    # can drop the stale identity, rather than logging "unauthorized" forever.
    calls = {"n": 0}

    async def _always_401(*_args: object, **_kwargs: object) -> dict:
        calls["n"] += 1
        raise _unauthorized()

    monkeypatch.setattr(main.control_plane, "heartbeat", _always_401)

    state = AgentState(agent_id="agent-1", agent_token="dead-token")
    with pytest.raises(main._AuthInvalidated):
        await main._heartbeat_loop(state, Mock())

    assert calls["n"] == main._REENROLL_AFTER_UNAUTHORIZED


def _scripted_heartbeat(beats: list[object]):
    """A control_plane.heartbeat stub that plays `beats` in order (an Exception is raised,
    a dict is returned), then ends the otherwise-infinite loop with CancelledError."""

    async def _heartbeat(*_args: object, **_kwargs: object) -> dict:
        if not beats:
            raise asyncio.CancelledError
        beat = beats.pop(0)
        if isinstance(beat, Exception):
            raise beat
        assert isinstance(beat, dict)
        return beat

    return _heartbeat


@pytest.mark.usefixtures("_instant_loop")
async def test_transient_unauthorized_recovers_without_reenroll(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A couple of 401s below the threshold, then a good beat, must NOT tear the agent down:
    # the streak resets and the agent simply announces it is online.
    beats: list[object] = [_unauthorized(), _unauthorized(), {"heartbeat_interval_seconds": 30}]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with caplog.at_level(logging.INFO, logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    messages = [record.getMessage() for record in caplog.records]
    assert any("Agent online" in message for message in messages)


@pytest.mark.usefixtures("_instant_loop")
async def test_online_is_announced_only_after_a_beat_is_accepted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The first call is rejected; "Agent online" must not appear until a beat is accepted, so
    # the log never claims the agent is up while its credentials are in fact being refused.
    beats: list[object] = [_unauthorized(), {"heartbeat_interval_seconds": 30}]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with caplog.at_level(logging.INFO, logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    messages = [record.getMessage() for record in caplog.records]
    online_index = next(i for i, m in enumerate(messages) if "Agent online" in m)
    unauthorized_index = next(i for i, m in enumerate(messages) if "unauthorized" in m)
    # the first 401 was reported, and "online" was announced strictly after it (never upfront).
    assert unauthorized_index < online_index


@pytest.mark.usefixtures("_instant_loop")
async def test_two_unauthorized_below_threshold_does_not_reenroll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The boundary: with the threshold at 3, two consecutive 401s must NOT raise. We feed
    # exactly two 401s then end the loop, and assert no _AuthInvalidated escaped.
    assert main._REENROLL_AFTER_UNAUTHORIZED == 3
    beats: list[object] = [_unauthorized(), _unauthorized()]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with pytest.raises(asyncio.CancelledError):  # the loop ends, never raising _AuthInvalidated
        await main._heartbeat_loop(state, Mock())


async def test_reenroll_returns_new_state_when_token_is_still_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The kept-volume case: ARES_TOKEN is unused, so re-enrollment succeeds and yields a new
    # identity for the caller to adopt.
    fresh = AgentState(agent_id="new", agent_token="agtk-new")

    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        return fresh

    monkeypatch.setattr(main, "_register", _register)
    assert await main._reenroll(["10.0.0.0/24"]) is fresh


async def test_reenroll_returns_none_when_token_is_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Decommissioned / healthy-transient case: the one-time token is already used, so re-enroll
    # fails and returns None. The caller must keep the existing credentials, not strand them.
    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        raise main.control_plane.RegistrationRejected("already used")

    monkeypatch.setattr(main, "_register", _register)
    assert await main._reenroll(["10.0.0.0/24"]) is None


async def test_reenroll_returns_none_when_ares_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(main, "_register", _register)
    assert await main._reenroll(["10.0.0.0/24"]) is None


async def test_run_adopts_a_fresh_identity_on_reenroll(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # End-to-end of the self-heal orchestration in run(): _serve raises _AuthInvalidated once,
    # run() re-enrolls and resumes serving with the NEW state (not the stale one), and never
    # exits the process to do it.
    stale = AgentState(agent_id="stale", agent_token="agtk-stale")
    fresh = AgentState(agent_id="fresh", agent_token="agtk-fresh")
    served: list[AgentState] = []

    async def _enroll(_networks: list[str]) -> AgentState:
        return stale

    async def _serve(state: AgentState, _tunnel: object) -> None:
        served.append(state)
        if len(served) == 1:
            raise main._AuthInvalidated
        raise asyncio.CancelledError  # stop the otherwise-infinite outer loop

    async def _reenroll(_networks: list[str]) -> AgentState:
        return fresh

    class _FakeTunnel:
        def __init__(self, *_args: object, **_kwargs: object) -> None: ...

        def stop(self) -> None: ...

    monkeypatch.setattr(main, "_enroll", _enroll)
    monkeypatch.setattr(main, "_serve", _serve)
    monkeypatch.setattr(main, "_reenroll", _reenroll)
    monkeypatch.setattr(main, "TunnelManager", _FakeTunnel)
    monkeypatch.setattr(main, "tunnel_url", lambda url: url)
    monkeypatch.setattr(main.netdetect, "detect_networks", lambda: ["10.0.0.0/24"])
    monkeypatch.setattr(main.settings, "token", SecretStr("ares_agt_fresh"))
    monkeypatch.setattr(main.settings, "insecure", False)
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)

    with pytest.raises(asyncio.CancelledError):
        await main.run()

    # served the stale identity first, then the freshly re-enrolled one.
    assert served == [stale, fresh]


# --- scan task orchestration: progress + live streaming + auto-scope ----------------------------


async def test_run_task_reports_progress_and_streams_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # _run_task must feed scan_cidr's callbacks straight to the control plane: percentages via
    # progress posts, and discovered hosts streamed as they are found, with the authoritative full
    # list sent on completion.
    started: list[str] = []
    progress: list[tuple[int, list[dict] | None]] = []
    completed: list[list[dict]] = []
    host = {"ip": "10.0.0.5", "port": 80, "service": "http", "protocol": "tcp", "evidence": "x"}

    async def _task_started(_s, _t, task_id):
        started.append(task_id)

    async def _task_progress(_s, _t, _task_id, *, percent, discovered_hosts=None, **_kw):
        progress.append((percent, discovered_hosts))

    async def _task_completed(_s, _t, _task_id, hosts, **_kw):
        completed.append(hosts)

    async def _fake_scan(cidr, ports, **kwargs):
        assert ports == [80]  # tool_config.ports is honoured
        await kwargs["on_progress"](50)
        await kwargs["on_hosts"]([host])
        await kwargs["on_progress"](100)
        return [host]

    monkeypatch.setattr(main.control_plane, "task_started", _task_started)
    monkeypatch.setattr(main.control_plane, "task_progress", _task_progress)
    monkeypatch.setattr(main.control_plane, "task_completed", _task_completed)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)

    await main._run_task(
        "tok",
        {"id": "t1", "target_network": "10.0.0.0/24", "tool_config": {"ports": [80]}},
    )

    assert started == ["t1"]
    assert completed == [[host]]
    percents = [p for p, _ in progress]
    assert 50 in percents and 100 in percents
    assert any(hosts == [host] for _, hosts in progress)  # a chunk was streamed live


async def test_run_task_survives_a_failed_progress_post(monkeypatch: pytest.MonkeyPatch) -> None:
    # a dropped progress post is best-effort: it must never fail the scan or block completion.
    completed: list[list[dict]] = []

    async def _ok(*_a, **_k):
        return None

    async def _boom(*_a, **_k):
        raise RuntimeError("network blip")

    async def _task_completed(_s, _t, _task_id, hosts, **_kw):
        completed.append(hosts)

    async def _fake_scan(cidr, ports, **kwargs):
        await kwargs["on_progress"](25)  # this post raises, and must be swallowed
        return []

    monkeypatch.setattr(main.control_plane, "task_started", _ok)
    monkeypatch.setattr(main.control_plane, "task_progress", _boom)
    monkeypatch.setattr(main.control_plane, "task_completed", _task_completed)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)

    await main._run_task("tok", {"id": "t1", "target_network": "10.0.0.0/24"})

    assert completed == [[]]  # completed cleanly despite the progress post blowing up


async def test_run_task_fails_without_a_target_network(monkeypatch: pytest.MonkeyPatch) -> None:
    failed: list[str] = []

    async def _task_failed(_s, _t, _task_id, reason):
        failed.append(reason)

    async def _should_not_run(*_a, **_k):
        raise AssertionError("scan must not start without a target network")

    monkeypatch.setattr(main.control_plane, "task_failed", _task_failed)
    monkeypatch.setattr(main.scan, "scan_cidr", _should_not_run)

    await main._run_task("tok", {"id": "t1"})

    assert failed == ["missing target_network"]


async def test_run_advertises_auto_scoped_networks(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # with ARES_NETWORKS unset, run() advertises whatever netdetect.scan_targets resolves for the
    # configured scope -- the operator never has to type a CIDR.
    captured: dict[str, list[str]] = {}

    async def _enroll(networks: list[str]) -> AgentState:
        captured["networks"] = networks
        raise asyncio.CancelledError  # stop run() right after it computes the target networks

    monkeypatch.setattr(main, "_enroll", _enroll)
    monkeypatch.setattr(main.netdetect, "scan_targets", lambda scope: ["10.9.0.0/16"])
    monkeypatch.setattr(main.settings, "token", SecretStr("ares_agt_x"))
    monkeypatch.setattr(main.settings, "insecure", False)
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)

    with pytest.raises(asyncio.CancelledError):
        await main.run()

    assert captured["networks"] == ["10.9.0.0/16"]


# --- network-resilience watchdog + bounded metrics ----------------------------------------------


@pytest.fixture
def _restore_liveness():
    """Snapshot/restore the module-level liveness clock so a test that backdates it does not
    bleed into the next."""
    saved = dict(main._liveness)
    yield
    main._liveness.clear()
    main._liveness.update(saved)


async def test_record_contact_bumps_liveness_and_writes_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path, _restore_liveness
) -> None:
    # a successful contact advances the watchdog clock and refreshes the healthcheck marker file.
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    main._liveness["last_contact"] = 0.0
    main._liveness["last_marker_at"] = 0.0  # ensure the throttle allows this first write

    main._record_contact()

    assert main._liveness["last_contact"] > 0.0
    marker = tmp_path / "last-contact"
    assert marker.exists()
    assert abs(time.time() - float(marker.read_text())) < 5  # a fresh epoch second was written


async def test_record_contact_throttles_the_marker_but_always_bumps_the_clock(
    monkeypatch: pytest.MonkeyPatch, tmp_path, _restore_liveness
) -> None:
    # the marker file is rewritten at most every _MARKER_MIN_INTERVAL_SECONDS (no /data churn on the
    # ~5s poll), but the in-memory watchdog clock advances on every contact.
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    monkeypatch.setattr(main, "_MARKER_MIN_INTERVAL_SECONDS", 999)
    main._liveness["last_marker_at"] = 0.0
    main._record_contact()  # first write allowed (last_marker_at was 0)
    marker = tmp_path / "last-contact"
    marker.unlink()  # remove it; a throttled second call must NOT recreate it
    main._liveness["last_contact"] = 0.0

    main._record_contact()

    assert not marker.exists()  # throttled: no rewrite within the interval
    assert main._liveness["last_contact"] > 0.0  # but the watchdog clock still advanced


async def test_watchdog_exits_when_contact_is_stale(
    monkeypatch: pytest.MonkeyPatch, _restore_liveness
) -> None:
    # no successful contact for longer than max_offline_seconds -> exit so the container restarts.
    class _Exited(Exception):
        pass

    codes: list[int] = []

    def _fake_exit(code: int) -> None:
        codes.append(code)
        raise _Exited  # stand in for os._exit so the test can observe it instead of dying

    monkeypatch.setattr(main.os, "_exit", _fake_exit)
    monkeypatch.setattr(main, "_WATCHDOG_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(main.settings, "max_offline_seconds", 1)
    main._liveness["last_contact"] = time.monotonic() - 10  # last contact well past the limit

    with pytest.raises(_Exited):
        await asyncio.wait_for(main._watchdog_loop(), timeout=2)
    assert codes == [1]  # non-zero: an unhealthy restart


async def test_watchdog_stays_quiet_while_contact_is_fresh(
    monkeypatch: pytest.MonkeyPatch, _restore_liveness
) -> None:
    # while contact is recent the watchdog leaves the process alone.
    exited: list[int] = []
    monkeypatch.setattr(main.os, "_exit", lambda code: exited.append(code))
    monkeypatch.setattr(main, "_WATCHDOG_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(main.settings, "max_offline_seconds", 600)
    main._liveness["last_contact"] = time.monotonic()

    with pytest.raises(asyncio.TimeoutError):  # it keeps watching (never exits) until cancelled
        await asyncio.wait_for(main._watchdog_loop(), timeout=0.2)
    assert exited == []


async def test_sample_cpu_percent_returns_none_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # a failing CPU read is best-effort: the beat proceeds with no CPU rather than raising.
    def _boom() -> float:
        raise RuntimeError("cgroup unreadable")

    monkeypatch.setattr(main, "read_cpu_percent", _boom)
    assert await main._sample_cpu_percent() is None


async def test_sample_cpu_percent_returns_none_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # a slow/starved sample must not wedge the beat: it is abandoned past the timeout.
    monkeypatch.setattr(main, "_CPU_SAMPLE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(main, "read_cpu_percent", lambda: time.sleep(0.5) or 12.3)
    assert await main._sample_cpu_percent() is None


def test_allowed_hosts_keeps_only_strings_and_never_widens() -> None:
    # ares pushes the hostname destinations of running hunts; anything malformed must degrade to
    # "no pushed hosts" (the registered networks stay the only way in), never to a wider set.
    assert main._allowed_hosts(["bank.internal", "echo.internal"]) == [
        "bank.internal",
        "echo.internal",
    ]
    assert main._allowed_hosts(["bank.internal", 42, None]) == ["bank.internal"]
    assert main._allowed_hosts(None) == []
    assert main._allowed_hosts("bank.internal") == []


# ── logging configuration: verbosity is ours to raise, never the dependencies' ──
def test_debug_log_level_does_not_enable_third_party_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ARES_LOG_LEVEL=DEBUG must raise our verbosity only.

    ``websockets`` logs every frame it relays at DEBUG and a frame's repr renders the payload as
    hex, so letting the level reach the root logger would hex-dump the customer's own tunnelled
    traffic (in plaintext whenever the target speaks http) into their agent log.
    """
    monkeypatch.setattr(main.settings, "log_level", "DEBUG")
    main._configure_logging()

    assert logging.getLogger("ares.agent.tunnel").isEnabledFor(logging.DEBUG)
    for noisy in ("websockets", "httpx", "httpcore", "asyncio"):
        assert not logging.getLogger(noisy).isEnabledFor(logging.DEBUG), noisy


def test_the_enrollment_token_never_renders_in_a_log_or_repr() -> None:
    """The token is the one credential this process holds; it must not be printable by accident."""
    from agent.config import Settings

    settings = Settings(token="super-secret-enrollment-token")  # type: ignore[arg-type]
    assert "super-secret-enrollment-token" not in repr(settings)
    assert "super-secret-enrollment-token" not in str(settings)
    assert "super-secret-enrollment-token" not in f"{settings.token}"
    # ...but the real value is still reachable where it is genuinely needed.
    assert settings.token.get_secret_value() == "super-secret-enrollment-token"
