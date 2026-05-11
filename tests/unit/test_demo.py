"""Demo integration tests — scanners mocked, fixture-based."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from orchestrator.demo import run_demo
from orchestrator.types import Finding


@pytest.fixture
def demo_findings() -> list[Finding]:
    """Findings that would be returned by scanners against sample-app."""
    return [
        Finding(
            source="checkov",
            rule_id="CKV_AWS_19",
            severity="high",
            file="/main.tf",
            line=11,
            message="Ensure the S3 bucket has server-side-encryption enabled",
            control_ids=["PCI-DSS-3.5.1"],
            product="",
        ),
        Finding(
            source="checkov",
            rule_id="CKV_AWS_24",
            severity="high",
            file="/main.tf",
            line=40,
            message="Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
            control_ids=["PCI-DSS-1.3.1"],
            product="",
        ),
        Finding(
            source="semgrep",
            rule_id="python.lang.security.injection.sql-injection",
            severity="high",
            file="src/app.py",
            line=46,
            message="Possible SQL injection via string concatenation",
            control_ids=["PCI-DSS-6.3.1"],
            product="",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-50782",
            severity="critical",
            file="requirements.txt",
            line=0,
            message="Bleichenbacher attack in python-cryptography",
            control_ids=["PCI-DSS-6.3.1"],
            product="",
        ),
        Finding(
            source="gitleaks",
            rule_id="aws-access-key-id",
            severity="critical",
            file="src/config.py",
            line=8,
            message="AWS Access Key",
            control_ids=["PCI-DSS-3.5.1"],
            product="",
        ),
    ]


@patch("orchestrator.demo.SbomGenerator")
@patch("orchestrator.demo.ScannerRunner")
@patch("orchestrator.demo.ControlMapper")
class TestDemo:
    def test_demo_runs_without_error(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        demo_findings: list[Finding],
        tmp_path: Path,
    ) -> None:
        """Fixture-based demo runs without raising."""
        self._setup_and_run(mock_mapper_cls, mock_runner_cls, mock_sbom_cls, demo_findings, tmp_path)

    def test_demo_produces_evidence_file(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        demo_findings: list[Finding],
        tmp_path: Path,
    ) -> None:
        """Demo produces evidence JSON in output/evidence/."""
        self._setup_and_run(mock_mapper_cls, mock_runner_cls, mock_sbom_cls, demo_findings, tmp_path)

        evidence_dir = tmp_path / "project" / "output" / "evidence"
        json_files = list(evidence_dir.glob("*.json"))
        assert len(json_files) >= 1

        report = json.loads(json_files[0].read_text())
        assert "report_id" in report
        assert "summary" in report

    def test_demo_produces_jsonl(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        demo_findings: list[Finding],
        tmp_path: Path,
    ) -> None:
        """Demo produces findings.jsonl."""
        self._setup_and_run(mock_mapper_cls, mock_runner_cls, mock_sbom_cls, demo_findings, tmp_path)

        jsonl_path = tmp_path / "project" / "output" / "findings.jsonl"
        assert jsonl_path.exists()

        lines = jsonl_path.read_text().strip().splitlines()
        assert len(lines) > 0

        first = json.loads(lines[0])
        assert first["type"] == "finding"

    def test_demo_produces_risk_assessment(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        demo_findings: list[Finding],
        tmp_path: Path,
    ) -> None:
        """Demo produces risk assessment YAML."""
        self._setup_and_run(mock_mapper_cls, mock_runner_cls, mock_sbom_cls, demo_findings, tmp_path)

        ra_dir = tmp_path / "project" / "controls" / "products" / "payment-api" / "risk-assessments"
        yaml_files = list(ra_dir.glob("RA-*.yaml"))
        assert len(yaml_files) >= 1

    @staticmethod
    def _setup_and_run(
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        findings: list[Finding],
        tmp_path: Path,
    ) -> None:
        """Set up a fake project root and run the demo."""
        import shutil

        project_root = tmp_path / "project"
        project_root.mkdir()

        # Copy controls from real project
        real_root = Path(__file__).resolve().parent.parent.parent
        shutil.copytree(real_root / "controls", project_root / "controls")
        shutil.copytree(real_root / "sigma", project_root / "sigma")

        # Ensure output dir
        (project_root / "output").mkdir()

        # Create sample log file for sigma detection
        log_dir = tmp_path / "target" / "logs"
        log_dir.mkdir(parents=True)
        log_entries = [
            '{"timestamp":"2026-04-19T10:00:01Z","event_type":"login_failed","username":"admin","ip":"192.168.1.100","reason":"invalid_password"}',
            '{"timestamp":"2026-04-19T10:00:04Z","event_type":"api_request","path":"/api/export?id=1 OR 1=1","method":"GET","status":400,"ip":"10.0.0.5"}',
        ]
        (log_dir / "access.jsonl").write_text("\n".join(log_entries) + "\n")

        # Mock scanners
        mock_mapper_cls.return_value = MagicMock()
        mock_mapper_cls.return_value.map_finding.return_value = []
        mock_runner = MagicMock()
        mock_runner.run_all.return_value = list(findings)
        mock_runner_cls.return_value = mock_runner

        # Mock SBOM generator
        from orchestrator.scanners.sbom import SbomResult

        mock_sbom = MagicMock()
        mock_sbom.generate.return_value = SbomResult(
            sbom_path=str(tmp_path / "sbom.json"),
            format="cyclonedx-json",
            components_count=3,
            raw_sbom={"components": []},
        )
        mock_sbom_cls.return_value = mock_sbom

        # Patch _PROJECT_ROOT and GrypeScanner for SBOM scan
        mock_grype = MagicMock()
        mock_grype.scan_sbom.return_value = []

        with patch("orchestrator.demo._PROJECT_ROOT", project_root):
            run_demo(str(tmp_path / "target"), product="payment-api")
