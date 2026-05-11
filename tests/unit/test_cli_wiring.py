"""CLI wiring tests — step 4 of phase 6-ai-pipeline-v2.

Validates:
1. Dashboard directory creation after risk-assess
2. index.json generation
3. Progress output in AI mode
4. Step numbering updated to [N/8]
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from orchestrator.cli import cli
from orchestrator.types import Finding


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def findings() -> list[Finding]:
    return [
        Finding(
            source="semgrep",
            rule_id=f"rule-{i}",
            severity="high",
            file="src/app.py",
            line=10 + i,
            message=f"Test finding {i}",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
        )
        for i in range(5)
    ]


def _setup_product_files(tmp_path: Path) -> None:
    """Create minimal fixture YAML files for risk-assess CLI tests."""
    product_dir = tmp_path / "controls" / "products" / "payment-api"
    product_dir.mkdir(parents=True, exist_ok=True)
    (product_dir / "risk-assessments").mkdir(exist_ok=True)

    manifest = {
        "product": {
            "name": "payment-api",
            "description": "test",
            "data_classification": ["PCI"],
            "jurisdiction": ["JP"],
            "deployment": {"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
            "integrations": [],
        }
    }
    (product_dir / "product-manifest.yaml").write_text(yaml.dump(manifest))

    profile = {
        "risk_profile": {
            "frameworks": ["pci-dss-4.0"],
            "risk_appetite": "conservative",
            "thresholds": {
                "critical": {
                    "max_critical_findings": 100,
                    "max_secrets_detected": 100,
                    "max_high_findings_pci": 100,
                    "action": "proceed",
                },
                "high": {"action": "proceed"},
                "medium": {"action": "proceed"},
                "low": {"action": "proceed"},
            },
            "failure_policy": {
                "critical": {"scan_failure": "proceed"},
                "high": {"scan_failure": "proceed"},
                "medium": {"scan_failure": "proceed"},
                "low": {"scan_failure": "proceed"},
            },
        }
    }
    (product_dir / "risk-profile.yaml").write_text(yaml.dump(profile))

    baselines_dir = tmp_path / "controls" / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    tier_mappings = {
        "tier_mappings": {
            "critical": {"frameworks": []},
            "high": {"frameworks": []},
            "medium": {"frameworks": []},
            "low": {"frameworks": []},
        }
    }
    (tmp_path / "controls" / "tier-mappings.yaml").write_text(yaml.dump(tier_mappings))

    # Rego dir
    rego_dir = tmp_path / "rego" / "gates"
    rego_dir.mkdir(parents=True, exist_ok=True)


def _invoke_risk_assess(
    runner: CliRunner,
    tmp_path: Path,
    findings: list[Finding],
    *,
    env: dict[str, str] | None = None,
) -> object:
    """Invoke risk-assess with mocked scanners and pipeline."""
    _setup_product_files(tmp_path)
    output_dir = tmp_path / "output"

    mock_runner = MagicMock()
    mock_runner.run_all.return_value = findings

    with (
        patch("orchestrator.cli.ScannerRunner", return_value=mock_runner),
        patch("orchestrator.cli.ControlMapper"),
        patch("orchestrator.cli._PROJECT_ROOT", tmp_path),
    ):
        result = runner.invoke(
            cli,
            [
                "risk-assess",
                str(tmp_path),
                "--product", "payment-api",
                "--output", str(output_dir),
            ],
            env=env or {},
        )
    return result


class TestRiskAssessCreatesDashboardDir:
    def test_risk_assess_creates_dashboard_dir(
        self, runner: CliRunner, tmp_path: Path, findings: list[Finding]
    ) -> None:
        """risk-assess creates output/dashboard/ directory."""
        result = _invoke_risk_assess(runner, tmp_path, findings)
        assert result.exit_code == 0, result.output
        dashboard_dir = tmp_path / "output" / "dashboard"
        assert dashboard_dir.is_dir()


class TestRiskAssessCreatesIndexJson:
    def test_risk_assess_creates_index_json(
        self, runner: CliRunner, tmp_path: Path, findings: list[Finding]
    ) -> None:
        """risk-assess creates output/dashboard/index.json."""
        result = _invoke_risk_assess(runner, tmp_path, findings)
        assert result.exit_code == 0, result.output
        index_path = tmp_path / "output" / "dashboard" / "index.json"
        assert index_path.exists()
        data = json.loads(index_path.read_text())
        assert "product" in data
        assert data["product"] == "payment-api"


class TestRiskAssessProgressOutput:
    def test_risk_assess_progress_output(
        self, runner: CliRunner, tmp_path: Path, findings: list[Finding]
    ) -> None:
        """AI mode shows per-finding progress [1/5]...[5/5]."""
        _setup_product_files(tmp_path)
        output_dir = tmp_path / "output"

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = findings

        # Mock Bedrock pipeline to invoke progress_callback
        from orchestrator.rmf.models import SP80030Report

        def fake_run(*, findings, enriched_vulns, manifest, controls, trigger, progress_callback=None):
            if progress_callback:
                for i in range(5):
                    progress_callback(i + 1, 5, f"rule-{i}")
            return SP80030Report(
                report_id="RA-TEST",
                product="payment-api",
                generated_at="2026-01-01T00:00:00Z",
                mode="ai",
                methodology="NIST SP 800-30 Rev 1",
                scope="test",
                risk_model="semi-quantitative",
                assumptions=[],
                cia_impact_levels={},
                threat_sources=[],
                threat_events=[],
                likelihood_assessments=[],
                impact_assessments=[],
                risk_determinations=[],
                executive_summary="test",
                risk_responses=[],
                recommendations=[],
                reassessment_triggers=[],
                next_review_date="2026-04-01",
            )

        mock_pipeline = MagicMock()
        mock_pipeline.run = MagicMock(side_effect=fake_run)

        mock_pipeline_cls = MagicMock(return_value=mock_pipeline)
        mock_bc_cls = MagicMock()

        with (
            patch("orchestrator.cli.ScannerRunner", return_value=mock_runner),
            patch("orchestrator.cli.ControlMapper"),
            patch("orchestrator.cli._PROJECT_ROOT", tmp_path),
            patch("orchestrator.cli.get_assessor", return_value=MagicMock(
                categorize=MagicMock(return_value=MagicMock(value="critical")),
            )),
            patch("orchestrator.cli.select_baseline", return_value=[]),
            patch.dict("os.environ", {"BEDROCK_MODEL_ID": "test-model"}),
            patch("orchestrator.assessor.bedrock_client.BedrockClient", mock_bc_cls),
            patch("orchestrator.rmf.pipeline.RiskAssessmentPipeline", mock_pipeline_cls),
        ):
            result = runner.invoke(
                cli,
                [
                    "risk-assess",
                    str(tmp_path),
                    "--product", "payment-api",
                    "--output", str(output_dir),
                ],
            )

        assert result.exit_code == 0, result.output
        assert "[1/5]" in result.output
        assert "[5/5]" in result.output


class TestRiskAssessStepNumbers8:
    def test_risk_assess_step_numbers_8(
        self, runner: CliRunner, tmp_path: Path, findings: list[Finding]
    ) -> None:
        """Step numbering uses [N/8] not [N/7]."""
        result = _invoke_risk_assess(runner, tmp_path, findings)
        assert result.exit_code == 0, result.output
        assert "[8/8]" in result.output
        assert "[1/8]" in result.output
        # Old numbering should not be present
        assert "[7/7]" not in result.output
