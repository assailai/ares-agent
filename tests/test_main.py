"""Control-plane loop resilience: failure logging is visible but never spammy, the
agent only claims to be online once a beat is accepted, and a sustained authorization
failure re-enrolls (non-destructively) instead of 401-looping forever or stranding a
healthy agent on a spent one-time token."""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import Mock

import httpx
import pytest

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
    monkeypatch.setattr(main.settings, "token", "ares_agt_fresh")
    monkeypatch.setattr(main.settings, "insecure", False)
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)

    with pytest.raises(asyncio.CancelledError):
        await main.run()

    # served the stale identity first, then the freshly re-enrolled one.
    assert served == [stale, fresh]
