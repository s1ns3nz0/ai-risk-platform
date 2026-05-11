"""Tests for Evidence export with DefectDojo integration."""

from __future__ import annotations

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
    defectdojo_client: MagicMock | None = None,
) -> EvidenceExporter:
    """Helper: set up JsonlWriter with findings and a mock ControlsRepository."""
    jsonl_path = tmp_path / "findings.jsonl"
    writer = JsonlWriter(str(jsonl_path))

    for f in findings or []:
        writer.write_finding(f)

    controls_repo = MagicMock()
    ctrl_list = controls or [_make_control()]
    controls_repo.controls = {c.id: c for c in ctrl_list}

    return EvidenceExporter(
        jsonl_reader=writer,
        controls_repo=controls_repo,
        defectdojo_client=defectdojo_client,
    )


class TestExportUsesJsonlWhenNoDefectdojo:
    def test_export_uses_jsonl_when_no_defectdojo(self, tmp_path: Path) -> None:
        """DefectDojo 없을 때 기존 JSONL 동작 유지."""
        finding = _make_finding()
        exporter = _setup_exporter(
            tmp_path,
            findings=[finding],
            controls=[_make_control()],
            defectdojo_client=None,
        )
        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        assert len(report["controls"]) == 1
        assert len(report["controls"][0]["evidence"]["findings"]) == 1
        assert report["controls"][0]["evidence"]["findings"][0]["source"] == "semgrep"


class TestExportPrefersDefectdojoWhenAvailable:
    def test_export_prefers_defectdojo_when_available(self, tmp_path: Path) -> None:
        """DefectDojo가 사용 가능하면 DefectDojo 데이터를 사용."""
        dd_client = MagicMock()
        dd_client.health_check.return_value = True
        dd_client.get_findings.return_value = [
            {
                "title": "sql-injection",
                "severity": "High",
                "description": "DD finding",
                "file_path": "src/api/export.py",
                "line": 42,
                "tags": ["PCI-DSS-6.3.1"],
            },
            {
                "title": "xss-reflected",
                "severity": "Medium",
                "description": "DD XSS finding",
                "file_path": "src/api/views.py",
                "line": 10,
                "tags": ["PCI-DSS-6.3.1"],
            },
        ]

        # JSONL has one finding, DefectDojo has two
        exporter = _setup_exporter(
            tmp_path,
            findings=[_make_finding()],
            controls=[_make_control()],
            defectdojo_client=dd_client,
        )
        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        # Should use DefectDojo data (2 findings, not JSONL's 1)
        assert report["controls"][0]["evidence"]["data_source"] == "defectdojo"
        assert len(report["controls"][0]["evidence"]["findings"]) == 2
        dd_client.health_check.assert_called_once()
        dd_client.get_findings.assert_called_once()


class TestDefectdojoFailureFallsBackToJsonl:
    def test_defectdojo_failure_falls_back_to_jsonl(self, tmp_path: Path) -> None:
        """DefectDojo 에러 시 JSONL fallback."""
        dd_client = MagicMock()
        dd_client.health_check.return_value = False

        finding = _make_finding()
        exporter = _setup_exporter(
            tmp_path,
            findings=[finding],
            controls=[_make_control()],
            defectdojo_client=dd_client,
        )
        report = exporter.export(
            product="payment-api",
            output_path=str(tmp_path / "evidence"),
        )

        # Should fallback to JSONL
        assert report["controls"][0]["evidence"]["data_source"] == "jsonl"
        assert len(report["controls"][0]["evidence"]["findings"]) == 1
        dd_client.get_findings.assert_not_called()
