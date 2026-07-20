"""agent.healthcheck.is_alive: the container liveness decision. Healthy only while the agent's
last-contact marker is fresh (within max_offline_seconds)."""

from __future__ import annotations

import pytest

from agent import healthcheck
from agent.config import settings


def test_alive_when_marker_is_fresh(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # given a marker written at t=1000 and a 600s limit
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(settings, "max_offline_seconds", 600)
    (tmp_path / "last-contact").write_text("1000")
    # when checked 10s later / then the agent is alive
    assert healthcheck.is_alive(now=1010) is True


def test_dead_when_marker_is_stale(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # given a marker older than the limit
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(settings, "max_offline_seconds", 600)
    (tmp_path / "last-contact").write_text("1000")
    # when checked well past the limit / then it is not alive
    assert healthcheck.is_alive(now=2000) is False


def test_dead_when_marker_is_missing(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # given no marker has ever been written (agent has never made contact)
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    # when checked / then it is not alive
    assert healthcheck.is_alive(now=1000) is False


def test_dead_when_marker_is_garbage(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # given a marker with unparseable contents
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    (tmp_path / "last-contact").write_text("not-a-number")
    # when checked / then it is not alive rather than crashing the probe
    assert healthcheck.is_alive(now=1000) is False
