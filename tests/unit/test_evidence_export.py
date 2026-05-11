"""Tests for Evidence report exporter."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.evidence.export import EvidenceExporter
from orchestrator.evidence.jsonl import JsonlWriter
from orchestrator.types import Finding, RiskTier


def _make_finding(
    source: str = "semgrep",
    rule_id: str = "sql-injection",
    control_ids: list[str] | None = None,
    product: str = "payment-api",
) -> Finding:
    return Finding(
        source=source,
        rule_id=rule_id,
        severity="high",
        file="src/api/export.py",
        line=42,
        message="Test finding",
        control_ids=control_ids or ["PCI-DSS-6.3.1"],
        product=product,
    )


def _make_control(
    control_id: str = "PCI-DSS-6.3.1",
    title: str = "Security vulnerabilities are identified and addressed",
    framework: str = "pci-dss-4.0",
    scanners: list[str] | None = None,
) -> Control:
    scanners = scanners or ["semgrep"]
    return Control(
        id=control_id,
        title=title,
        framework=framework,
        description="Test control",
        verification_methods=[VerificationMethod(scanner=s) for s in scanners],
        applicable_tiers=[RiskTier.HIGH, RiskTier.CRITICAL],
    )


def _setup_exporter(
    tmp_path: Path,
    findings: list[Finding] | None = None,
    controls: list[Control] | None = None,
) -> EvidenceExporter:
    """Helper: set up JsonlWriter with findings and a mock ControlsRepository."""
    jsonl_path = tmp_path / "findings.jsonl"
    writer = JsonlWriter(str(jsonl_path))

    for f in findings or []:
        writer.write_finding(f)

    controls_repo = MagicMock()
    ctrl_list = controls or [_make_control()]
    controls_repo.controls = {c.id: c for c in ctrl_list}

    return EvidenceExporter(jsonl_reader=writer, controls_repo=controls_repo)


class TestExportReport:
    def test_export_produces_valid_report(self, tmp_path: Path) -> None:
        """report에 필수 필드 포함."""
        exporter = _setup_exporter(
            tmp_path,
            findings=[_make_finding()],
            controls=[_make_control()],
        )
        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        assert "report_id" in report
        assert report["report_id"].startswith("EVD-")
        assert "generated_at" in report
        assert report["product"] == "payment-api"
        assert "controls" in report
        assert "summary" in report
        assert "total_controls" in report["summary"]
        assert "coverage_percentage" in report["summary"]

    def test_export_filter_by_control_id(self, tmp_path: Path) -> None:
        """특정 control만 포함."""
        controls = [
            _make_control("PCI-DSS-6.3.1"),
            _make_control("ASVS-V5.3.4", framework="asvs-4.0.3-L3"),
        ]
        exporter = _setup_exporter(
            tmp_path,
            findings=[_make_finding(control_ids=["PCI-DSS-6.3.1"])],
            controls=controls,
        )
        report = exporter.export(
            product="payment-api",
            control_id="PCI-DSS-6.3.1",
            output_path=str(tmp_path / "evidence"),
        )

        assert len(report["controls"]) == 1
        assert report["controls"][0]["control_id"] == "PCI-DSS-6.3.1"


class TestControlStatus:
    def test_export_control_status_full(self, tmp_path: Path) -> None:
        """모든 scanner 결과 있음 -> 'full'."""
        control = _make_control("PCI-DSS-6.3.1", scanners=["semgrep"])
        findings = [_make_finding(source="semgrep", control_ids=["PCI-DSS-6.3.1"])]
        exporter = _setup_exporter(tmp_path, findings=findings, controls=[control])

        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        assert report["controls"][0]["status"] == "full"

    def test_export_control_status_partial(self, tmp_path: Path) -> None:
        """일부 scanner 결과만 -> 'partial'."""
        control = _make_control("PCI-DSS-6.3.1", scanners=["semgrep", "grype"])
        findings = [_make_finding(source="semgrep", control_ids=["PCI-DSS-6.3.1"])]
        exporter = _setup_exporter(tmp_path, findings=findings, controls=[control])

        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        assert report["controls"][0]["status"] == "partial"

    def test_export_control_status_none(self, tmp_path: Path) -> None:
        """결과 없음 -> 'none'."""
        control = _make_control("PCI-DSS-6.3.1", scanners=["semgrep"])
        exporter = _setup_exporter(tmp_path, findings=[], controls=[control])

        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        assert report["controls"][0]["status"] == "none"


class TestCoverage:
    def test_export_coverage_percentage(self, tmp_path: Path) -> None:
        """coverage 계산 정확성."""
        controls = [
            _make_control("PCI-DSS-6.3.1", scanners=["semgrep"]),
            _make_control("ASVS-V5.3.4", framework="asvs-4.0.3-L3", scanners=["semgrep"]),
            _make_control("FISC-OP-1", framework="fisc-safety", scanners=["checkov"]),
        ]
        findings = [
            _make_finding(source="semgrep", control_ids=["PCI-DSS-6.3.1"]),
            _make_finding(source="semgrep", control_ids=["ASVS-V5.3.4"]),
        ]
        exporter = _setup_exporter(tmp_path, findings=findings, controls=controls)

        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        summary = report["summary"]
        assert summary["total_controls"] == 3
        assert summary["fully_evidenced"] == 2
        assert summary["no_evidence"] == 1
        # 2 full + 0 partial out of 3 => (2/3)*100 ~ 66.7
        assert abs(summary["coverage_percentage"] - 66.7) < 0.1


class TestOutputFile:
    def test_export_writes_json_file(self, tmp_path: Path) -> None:
        """output 디렉토리에 JSON 파일 생성."""
        exporter = _setup_exporter(
            tmp_path,
            findings=[_make_finding()],
            controls=[_make_control()],
        )
        output_dir = tmp_path / "evidence"
        report = exporter.export(
            product="payment-api",
            output_path=str(output_dir),
        )

        # Directory should be created
        assert output_dir.exists()
        # At least one JSON file should exist
        json_files = list(output_dir.glob("*.json"))
        assert len(json_files) == 1

        # File content should match returned report
        with open(json_files[0]) as f:
            saved = json.load(f)
        assert saved["report_id"] == report["report_id"]
