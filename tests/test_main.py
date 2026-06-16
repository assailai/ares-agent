"""Control-plane loop resilience: failure logging is visible but never spammy."""

from __future__ import annotations

import logging

import pytest

from agent.main import _log_repeated_failure


def test_repeated_failure_logging_escalates_then_quiets(caplog: pytest.LogCaptureFixture) -> None:
    # the first failure and every tenth are WARNING (visible at the default INFO level) so a
    # sustained outage is never silent; the noisy middle stays DEBUG so a flaky minute does not
    # flood the log.
    exc = RuntimeError("boom")
    with caplog.at_level(logging.DEBUG, logger="ares.agent"):
        _log_repeated_failure("heartbeat", 1, exc)
        _log_repeated_failure("heartbeat", 5, exc)
        _log_repeated_failure("heartbeat", 10, exc)

    by_message = {record.getMessage(): record.levelno for record in caplog.records}
    assert by_message["heartbeat failing (attempt 1): boom"] == logging.WARNING
    assert by_message["heartbeat failed (attempt 5): boom"] == logging.DEBUG
    assert by_message["heartbeat failing (attempt 10): boom"] == logging.WARNING
