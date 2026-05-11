"""Tests for JSONL evidence writer."""

from __future__ import annotations

import json
from pathlib import Path

from orchestrator.evidence.jsonl import JsonlWriter
from orchestrator.types import Finding, GateDecision


def _make_finding(
    source: str = "semgrep",
    rule_id: str = "sql-injection",
    severity: str = "high",
    file: str = "src/api/export.py",
    line: int = 42,
    product: str = "payment-api",
    control_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        source=source,
        rule_id=rule_id,
        severity=severity,
        file=file,
        line=line,
        message="Test finding",
        control_ids=control_ids or ["PCI-DSS-6.3.1"],
        product=product,
    )


def _make_gate_decision(passed: bool = True) -> GateDecision:
    return GateDecision(
        passed=passed,
        reason="All thresholds passed",
        threshold_results=[{"check": "critical_findings", "passed": True}],
        findings_count={"critical": 0, "high": 1},
    )


class TestWriteFinding:
    def test_write_finding_appends_to_file(self, tmp_path: Path) -> None:
        """finding 1개 작성 -> 파일에 1줄 추가."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_finding(_make_finding())

        lines = out.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["type"] == "finding"
        assert entry["data"]["source"] == "semgrep"

    def test_write_findings_appends_multiple(self, tmp_path: Path) -> None:
        """3개 findings -> 3줄 추가."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        findings = [
            _make_finding(source="semgrep"),
            _make_finding(source="grype", rule_id="CVE-2023-1234"),
            _make_finding(source="gitleaks", rule_id="aws-key"),
        ]
        writer.write_findings(findings)

        lines = out.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_finding_entry_has_timestamp(self, tmp_path: Path) -> None:
        """각 엔트리에 timestamp 포함."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_finding(_make_finding())

        entry = json.loads(out.read_text().strip())
        assert "timestamp" in entry
        # ISO format check
        assert "T" in entry["timestamp"]

    def test_finding_entry_has_hash(self, tmp_path: Path) -> None:
        """각 엔트리에 고유 hash 포함."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_finding(_make_finding(), commit_sha="abc123")

        entry = json.loads(out.read_text().strip())
        assert "hash" in entry
        assert len(entry["hash"]) > 0

    def test_append_not_overwrite(self, tmp_path: Path) -> None:
        """append-only: 두 번 쓰면 2줄."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_finding(_make_finding(source="semgrep"))
        writer.write_finding(_make_finding(source="grype"))

        lines = out.read_text().strip().splitlines()
        assert len(lines) == 2


class TestReadFindings:
    def test_read_findings_filter_by_product(self, tmp_path: Path) -> None:
        """product 필터링."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_finding(_make_finding(product="payment-api"))
        writer.write_finding(_make_finding(product="user-service"))
        writer.write_finding(_make_finding(product="payment-api"))

        results = writer.read_findings(product="payment-api")
        assert len(results) == 2
        assert all(r["data"]["product"] == "payment-api" for r in results)

    def test_read_findings_filter_by_control_id(self, tmp_path: Path) -> None:
        """control_id 필터링."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_finding(_make_finding(control_ids=["PCI-DSS-6.3.1"]))
        writer.write_finding(_make_finding(control_ids=["ASVS-V5.3.4"]))
        writer.write_finding(_make_finding(control_ids=["PCI-DSS-6.3.1", "ASVS-V5.3.4"]))

        results = writer.read_findings(control_id="PCI-DSS-6.3.1")
        assert len(results) == 2


class TestWriteGateDecision:
    def test_write_gate_decision(self, tmp_path: Path) -> None:
        """gate decision JSONL 기록."""
        out = tmp_path / "findings.jsonl"
        writer = JsonlWriter(str(out))

        writer.write_gate_decision(_make_gate_decision(), product="payment-api")

        entry = json.loads(out.read_text().strip())
        assert entry["type"] == "gate_decision"
        assert entry["data"]["passed"] is True
        assert entry["data"]["product"] == "payment-api"
        assert "timestamp" in entry
