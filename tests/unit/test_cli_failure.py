"""CLI failure policy integration tests — assess + status commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from orchestrator.cli import cli
from orchestrator.resilience.retry import RetryResult
from orchestrator.types import Finding


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def cli_findings() -> list[Finding]:
    return [
        Finding(
            source="checkov",
            rule_id="CKV_AWS_19",
            severity="high",
            file="main.tf",
            line=10,
            message="S3 bucket without encryption",
            control_ids=["PCI-DSS-3.5.1"],
            product="payment-api",
        ),
    ]


def _setup_product_files(
    tmp_path: Path,
    *,
    tier_failure_policy: str = "block",
    thresholds_block: bool = False,
) -> None:
    """Create minimal fixture YAML files for CLI tests."""
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

    action = "block" if thresholds_block else "proceed"
    profile = {
        "risk_profile": {
            "frameworks": ["pci-dss-4.0"],
            "risk_appetite": "conservative",
            "thresholds": {
                "critical": {
                    "max_critical_findings": 0,
                    "max_secrets_detected": 0,
                    "max_high_findings_pci": 0,
                    "action": action,
                },
                "high": {"action": "proceed"},
                "medium": {"action": "proceed"},
                "low": {"action": "proceed"},
            },
            "failure_policy": {
                "critical": {"scan_failure": tier_failure_policy},
                "high": {"scan_failure": "block"},
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


def _common_assess_args(tmp_path: Path) -> list[str]:
    return [
        "assess",
        str(tmp_path),
        "--product", "payment-api",
        "--controls-dir", str(tmp_path / "controls" / "baselines"),
        "--tier-mappings", str(tmp_path / "controls" / "tier-mappings.yaml"),
        "--product-dir", str(tmp_path / "controls" / "products" / "payment-api"),
        "--output-jsonl", str(tmp_path / "findings.jsonl"),
    ]


class TestAssessProceedsWhenAllScannersSucceed:
    """Existing behaviour preserved: no retry_config → no failure policy step."""

    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_assess_proceeds_when_all_scanners_succeed(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        _setup_product_files(tmp_path)

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = []
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        result = runner.invoke(cli, _common_assess_args(tmp_path))
        assert result.exit_code == 0
        # No failure policy step shown when no retry_config
        assert "Failure policy" not in result.output


class TestAssessBlocksOnScannerFailureCriticalTier:
    """Critical tier + scanner failure → exit 1."""

    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_assess_blocks_on_scanner_failure_critical_tier(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
        cli_findings: list[Finding],
    ) -> None:
        _setup_product_files(tmp_path, tier_failure_policy="block")

        retry_results = [
            RetryResult(scanner="checkov", success=True, attempts=1, total_time=1.0, error_message=""),
            RetryResult(scanner="semgrep", success=False, attempts=3, total_time=60.0, error_message="timeout"),
        ]

        mock_runner = MagicMock()
        mock_runner.run_all_with_retry.return_value = (cli_findings, retry_results)
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        args = _common_assess_args(tmp_path) + ["--retry"]
        result = runner.invoke(cli, args)
        assert result.exit_code == 1
        assert "BLOCKED" in result.output
        assert "semgrep" in result.output


class TestAssessWarnsOnScannerFailureMediumTier:
    """Medium tier + scanner failure → warn and proceed."""

    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_assess_warns_on_scanner_failure_medium_tier(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        _setup_product_files(tmp_path, tier_failure_policy="proceed")

        # Override tier to medium by using PII-general data classification
        product_dir = tmp_path / "controls" / "products" / "payment-api"
        manifest = {
            "product": {
                "name": "payment-api",
                "description": "test",
                "data_classification": ["public"],
                "jurisdiction": ["JP"],
                "deployment": {"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
                "integrations": [],
            }
        }
        (product_dir / "product-manifest.yaml").write_text(yaml.dump(manifest))

        retry_results = [
            RetryResult(scanner="checkov", success=True, attempts=1, total_time=1.0, error_message=""),
            RetryResult(scanner="semgrep", success=False, attempts=3, total_time=60.0, error_message="timeout"),
        ]

        mock_runner = MagicMock()
        mock_runner.run_all_with_retry.return_value = ([], retry_results)
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        args = _common_assess_args(tmp_path) + ["--retry"]
        result = runner.invoke(cli, args)
        # Should proceed (exit 0) despite scanner failure — medium tier warns only
        assert result.exit_code == 0
        assert "warn" in result.output.lower()


class TestAssessWithForceOverride:
    """--force-override → create override record, continue despite block."""

    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_assess_with_force_override(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
        cli_findings: list[Finding],
    ) -> None:
        _setup_product_files(tmp_path, tier_failure_policy="block")

        retry_results = [
            RetryResult(scanner="checkov", success=True, attempts=1, total_time=1.0, error_message=""),
            RetryResult(scanner="semgrep", success=False, attempts=3, total_time=60.0, error_message="timeout"),
        ]

        mock_runner = MagicMock()
        mock_runner.run_all_with_retry.return_value = (cli_findings, retry_results)
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        args = _common_assess_args(tmp_path) + [
            "--retry",
            "--force-override",
            "--override-reason", "scanner_timeout",
            "--override-justification", "Semgrep outage, will re-scan within 4h",
        ]
        result = runner.invoke(cli, args)
        # Should proceed (exit 0) — override granted
        assert result.exit_code == 0
        assert "OVERRIDE GRANTED" in result.output
        assert "OVR-" in result.output

        # Override recorded in JSONL
        jsonl_path = tmp_path / "findings.jsonl"
        if jsonl_path.exists():
            lines = jsonl_path.read_text().strip().splitlines()
            override_lines = [
                json.loads(line) for line in lines if json.loads(line).get("type") == "override"
            ]
            assert len(override_lines) >= 1


class TestOverrideRequiresReason:
    """--force-override without --override-reason → error."""

    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_override_requires_reason(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
        cli_findings: list[Finding],
    ) -> None:
        _setup_product_files(tmp_path, tier_failure_policy="block")

        retry_results = [
            RetryResult(scanner="semgrep", success=False, attempts=3, total_time=60.0, error_message="timeout"),
        ]

        mock_runner = MagicMock()
        mock_runner.run_all_with_retry.return_value = (cli_findings, retry_results)
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        args = _common_assess_args(tmp_path) + [
            "--retry",
            "--force-override",
            # No --override-reason provided
        ]
        result = runner.invoke(cli, args)
        assert result.exit_code == 1
        assert "--override-reason" in result.output


class TestStatusCommand:
    """status command shows pending overrides."""

    def test_status_shows_pending_overrides(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        jsonl_path = tmp_path / "findings.jsonl"

        # Write an override entry
        override_entry = {
            "type": "override",
            "timestamp": "2026-04-22T10:00:00+00:00",
            "data": {
                "id": "OVR-2026-0422-001",
                "product": "payment-api",
                "tier": "critical",
                "failed_scanners": ["semgrep"],
                "reason": "scanner_timeout",
                "justification": "Semgrep outage",
                "approver": "force-override",
                "deferred_scan_sla": "2026-04-22T14:00:00+00:00",
            },
        }
        jsonl_path.write_text(json.dumps(override_entry) + "\n")

        result = runner.invoke(
            cli,
            ["status", "--product", "payment-api", "--jsonl-path", str(jsonl_path)],
        )
        assert result.exit_code == 0
        assert "OVR-2026-0422-001" in result.output
        assert "payment-api" in result.output
        assert "scanner_timeout" in result.output

    def test_status_no_overrides(self, runner: CliRunner, tmp_path: Path) -> None:
        jsonl_path = tmp_path / "findings.jsonl"
        jsonl_path.write_text("")

        result = runner.invoke(
            cli,
            ["status", "--jsonl-path", str(jsonl_path)],
        )
        assert result.exit_code == 0
        assert "No pending overrides" in result.output
