"""Tests for ScannerRunner — aggregation and failure handling."""

from __future__ import annotations

from unittest.mock import MagicMock

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


class TestRunAllAggregatesFindings:
    def test_aggregates_from_multiple_scanners(self) -> None:
        scanner_a = MagicMock()
        scanner_a.name = "scanner-a"
        scanner_a.scan.return_value = [_make_finding("scanner-a", "rule-1")]

        scanner_b = MagicMock()
        scanner_b.name = "scanner-b"
        scanner_b.scan.return_value = [
            _make_finding("scanner-b", "rule-2"),
            _make_finding("scanner-b", "rule-3"),
        ]

        runner = ScannerRunner(scanners=[scanner_a, scanner_b])
        findings = runner.run_all("/target")

        assert len(findings) == 3
        sources = {f.source for f in findings}
        assert sources == {"scanner-a", "scanner-b"}


class TestScannerFailureDoesNotStopOthers:
    def test_failing_scanner_logs_and_continues(self) -> None:
        scanner_fail = MagicMock()
        scanner_fail.name = "broken"
        scanner_fail.scan.side_effect = RuntimeError("scanner crashed")

        scanner_ok = MagicMock()
        scanner_ok.name = "working"
        scanner_ok.scan.return_value = [_make_finding("working", "rule-ok")]

        runner = ScannerRunner(scanners=[scanner_fail, scanner_ok])
        findings = runner.run_all("/target")

        assert len(findings) == 1
        assert findings[0].source == "working"
