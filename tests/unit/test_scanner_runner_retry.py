"""Tests for ScannerRunner retry integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from orchestrator.resilience.retry import RetryConfig
from orchestrator.scanners.runner import ScannerRunner
from orchestrator.types import Finding


def _make_finding(source: str, rule_id: str) -> Finding:
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


class TestRunnerWithoutRetryConfig:
    def test_runner_without_retry_config(self) -> None:
        """기존 동작 유지 — log-and-continue, no retry."""
        scanner_fail = MagicMock()
        scanner_fail.name = "broken"
        scanner_fail.scan.side_effect = RuntimeError("crash")

        scanner_ok = MagicMock()
        scanner_ok.name = "working"
        scanner_ok.scan.return_value = [_make_finding("working", "rule-1")]

        runner = ScannerRunner(scanners=[scanner_fail, scanner_ok])
        result = runner.run_all("/target")

        # Backward-compatible: returns list[Finding]
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].source == "working"
        # Failed scanner called only once (no retry)
        scanner_fail.scan.assert_called_once()


class TestRunnerWithRetryConfig:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_runner_with_retry_config(self, mock_sleep: MagicMock) -> None:
        """실패 scanner 재시도 후 결과 반환."""
        scanner_flaky = MagicMock()
        scanner_flaky.name = "flaky"
        expected = [_make_finding("flaky", "rule-1")]
        scanner_flaky.scan.side_effect = [RuntimeError("transient"), expected]

        scanner_ok = MagicMock()
        scanner_ok.name = "stable"
        scanner_ok.scan.return_value = [_make_finding("stable", "rule-2")]

        config = RetryConfig()
        runner = ScannerRunner(scanners=[scanner_flaky, scanner_ok], retry_config=config)
        findings, retry_results = runner.run_all_with_retry("/target")

        assert len(findings) == 2
        sources = {f.source for f in findings}
        assert sources == {"flaky", "stable"}


class TestRunnerReturnsRetryResults:
    @patch("orchestrator.resilience.retry.time.sleep")
    def test_runner_returns_retry_results(self, mock_sleep: MagicMock) -> None:
        """RetryResult 목록 반환."""
        scanner_a = MagicMock()
        scanner_a.name = "scanner-a"
        scanner_a.scan.return_value = [_make_finding("scanner-a", "r1")]

        scanner_b = MagicMock()
        scanner_b.name = "scanner-b"
        scanner_b.scan.side_effect = RuntimeError("fail")

        config = RetryConfig()
        runner = ScannerRunner(scanners=[scanner_a, scanner_b], retry_config=config)
        findings, retry_results = runner.run_all_with_retry("/target")

        assert len(retry_results) == 2

        result_a = next(r for r in retry_results if r.scanner == "scanner-a")
        assert result_a.success is True
        assert result_a.attempts == 1

        result_b = next(r for r in retry_results if r.scanner == "scanner-b")
        assert result_b.success is False
        assert result_b.attempts == 3
