"""Tests for RetryEngine — retry logic with backoff and timeout."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from orchestrator.resilience.retry import RetryConfig, RetryEngine
from orchestrator.types import Finding


def _make_finding(source: str = "test", rule_id: str = "rule-1") -> Finding:
    return Finding(
        source=source,
        rule_id=rule_id,
        severity="high",
        file="test.py",
        line=1,
        message="test finding",
        control_ids=[],
        product="test",
    )


class TestSuccessOnFirstAttempt:
    def test_success_on_first_attempt(self) -> None:
        engine = RetryEngine()
        expected = [_make_finding()]
        scan_fn = MagicMock(return_value=expected)

        findings, result = engine.execute_with_retry("checkov", scan_fn)

        assert findings == expected
        assert result.success is True
        assert result.attempts == 1
        assert result.error_message == ""
        assert result.scanner == "checkov"
        scan_fn.assert_called_once()


class TestSuccessOnSecondAttempt:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_success_on_second_attempt(self, mock_sleep: MagicMock) -> None:
        engine = RetryEngine()
        expected = [_make_finding()]
        scan_fn = MagicMock(side_effect=[RuntimeError("timeout"), expected])

        findings, result = engine.execute_with_retry("semgrep", scan_fn)

        assert findings == expected
        assert result.success is True
        assert result.attempts == 2
        assert result.error_message == ""
        assert scan_fn.call_count == 2
        mock_sleep.assert_called_once_with(10.0)


class TestAllRetriesExhausted:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_all_retries_exhausted(self, mock_sleep: MagicMock) -> None:
        engine = RetryEngine()
        scan_fn = MagicMock(side_effect=RuntimeError("always fails"))

        findings, result = engine.execute_with_retry("grype", scan_fn)

        assert findings == []
        assert result.success is False
        assert result.attempts == 3
        assert "always fails" in result.error_message
        assert result.scanner == "grype"
        assert scan_fn.call_count == 3


class TestBackoffScheduleRespected:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_backoff_schedule_respected(self, mock_sleep: MagicMock) -> None:
        engine = RetryEngine()
        scan_fn = MagicMock(side_effect=RuntimeError("fail"))

        engine.execute_with_retry("checkov", scan_fn)

        # After attempt 1 fails: sleep 10s, after attempt 2 fails: sleep 30s
        # After attempt 3 fails: no more sleep (exhausted)
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(10.0)
        mock_sleep.assert_any_call(30.0)


class TestTotalTimeoutCap:
    @patch("orchestrator.resilience.retry.time.monotonic")
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_total_timeout_cap(
        self, mock_sleep: MagicMock, mock_monotonic: MagicMock
    ) -> None:
        config = RetryConfig(total_timeout=50.0)
        engine = RetryEngine(config=config)

        # t=0 (start), t=45 (after attempt 1 fails, elapsed check → 45 < 50 → sleep),
        # t=55 (after attempt 2 fails, elapsed check → 55 >= 50 → stop), t=60 (final)
        mock_monotonic.side_effect = [0.0, 45.0, 55.0, 60.0]
        scan_fn = MagicMock(side_effect=RuntimeError("slow"))

        findings, result = engine.execute_with_retry("checkov", scan_fn)

        assert findings == []
        assert result.success is False
        assert result.attempts == 2
        # Only slept once (after attempt 1), stopped before attempt 3
        assert mock_sleep.call_count == 1


class TestRetryResultContainsError:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_retry_result_contains_error(self, mock_sleep: MagicMock) -> None:
        engine = RetryEngine()
        scan_fn = MagicMock(side_effect=ValueError("specific error detail"))

        findings, result = engine.execute_with_retry("gitleaks", scan_fn)

        assert result.success is False
        assert "specific error detail" in result.error_message


class TestCustomConfig:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_custom_max_attempts(self, mock_sleep: MagicMock) -> None:
        config = RetryConfig(max_attempts=2, backoff_schedule=[5.0, 10.0])
        engine = RetryEngine(config=config)
        scan_fn = MagicMock(side_effect=RuntimeError("fail"))

        findings, result = engine.execute_with_retry("test", scan_fn)

        assert result.attempts == 2
        assert scan_fn.call_count == 2
