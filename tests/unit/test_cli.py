"""CLI command tests — all scanners mocked, using click.testing.CliRunner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from orchestrator.cli import cli
from orchestrator.types import Finding


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def cli_findings() -> list[Finding]:
    return [
        Finding(
            source="semgrep",
            rule_id="python.django.security.injection.sql-injection",
            severity="high",
            file="src/api/export.py",
            line=42,
            message="Possible SQL injection",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
        ),
    ]


class TestCliHelp:
    def test_cli_help(self, runner: CliRunner) -> None:
        """python -m orchestrator --help shows all commands."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "init" in result.output
        assert "scan" in result.output
        assert "assess" in result.output
        assert "export" in result.output
        assert "detect" in result.output


class TestInitCommand:
    def test_init_creates_manifest(self, runner: CliRunner, tmp_path: Path) -> None:
        """init command creates product-manifest.yaml and risk-profile.yaml."""
        controls_dir = tmp_path / "controls" / "products"
        controls_dir.mkdir(parents=True)

        user_input = "\n".join([
            "my-service",           # product name
            "A test service",       # description
            "PCI",                  # data classification
            "JP",                   # jurisdiction
            "AWS",                  # cloud
            "EKS",                  # compute
            "ap-northeast-1",       # region
        ]) + "\n"

        result = runner.invoke(
            cli,
            ["init", "--output-dir", str(controls_dir)],
            input=user_input,
        )
        assert result.exit_code == 0

        product_dir = controls_dir / "my-service"
        assert (product_dir / "product-manifest.yaml").exists()
        assert (product_dir / "risk-profile.yaml").exists()


class TestAssessCommand:
    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_assess_exit_code_0_on_pass(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Gate pass -> exit code 0."""
        self._setup_product_files(tmp_path)

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = []
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        result = runner.invoke(
            cli,
            [
                "assess", str(tmp_path),
                "--product", "payment-api",
                "--controls-dir", str(tmp_path / "controls" / "baselines"),
                "--tier-mappings", str(tmp_path / "controls" / "tier-mappings.yaml"),
                "--product-dir", str(tmp_path / "controls" / "products" / "payment-api"),
                "--output-jsonl", str(tmp_path / "findings.jsonl"),
            ],
        )
        assert result.exit_code == 0

    @patch("orchestrator.cli.ScannerRunner")
    @patch("orchestrator.cli.ControlMapper")
    def test_assess_exit_code_1_on_fail(
        self,
        mock_mapper_cls: MagicMock,
        mock_runner_cls: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
        cli_findings: list[Finding],
    ) -> None:
        """Gate fail -> exit code 1."""
        self._setup_product_files(tmp_path, thresholds_block=True)

        mock_runner = MagicMock()
        mock_runner.run_all.return_value = cli_findings
        mock_runner_cls.return_value = mock_runner
        mock_mapper_cls.return_value = MagicMock()

        result = runner.invoke(
            cli,
            [
                "assess", str(tmp_path),
                "--product", "payment-api",
                "--controls-dir", str(tmp_path / "controls" / "baselines"),
                "--tier-mappings", str(tmp_path / "controls" / "tier-mappings.yaml"),
                "--product-dir", str(tmp_path / "controls" / "products" / "payment-api"),
                "--output-jsonl", str(tmp_path / "findings.jsonl"),
            ],
        )
        assert result.exit_code == 1

    @staticmethod
    def _setup_product_files(tmp_path: Path, *, thresholds_block: bool = False) -> None:
        """Create minimal fixture YAML files for CLI tests."""
        import yaml

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
                    "critical": {"scan_failure": "block"},
                    "high": {"scan_failure": "proceed"},
                    "medium": {"scan_failure": "proceed"},
                    "low": {"scan_failure": "proceed"},
                },
            }
        }
        (product_dir / "risk-profile.yaml").write_text(yaml.dump(profile))

        # Minimal baselines dir + tier-mappings
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


class TestExportCommand:
    def test_export_creates_json(self, runner: CliRunner, tmp_path: Path) -> None:
        """export command creates a JSON evidence file."""
        import yaml

        # Create JSONL with a finding
        jsonl_path = tmp_path / "findings.jsonl"
        entry = {
            "type": "finding",
            "timestamp": "2026-04-20T00:00:00+00:00",
            "hash": "abc123",
            "data": {
                "source": "semgrep",
                "rule_id": "test-rule",
                "severity": "high",
                "file": "test.py",
                "line": 1,
                "message": "test",
                "control_ids": [],
                "product": "payment-api",
            },
        }
        jsonl_path.write_text(json.dumps(entry) + "\n")

        # Minimal baselines + tier-mappings
        baselines_dir = tmp_path / "baselines"
        baselines_dir.mkdir()
        tier_mappings = {
            "tier_mappings": {
                "critical": {"frameworks": []},
                "high": {"frameworks": []},
                "medium": {"frameworks": []},
                "low": {"frameworks": []},
            }
        }
        (tmp_path / "tier-mappings.yaml").write_text(yaml.dump(tier_mappings))

        output_dir = tmp_path / "evidence"

        result = runner.invoke(
            cli,
            [
                "export",
                "--product", "payment-api",
                "--output", str(output_dir),
                "--jsonl-path", str(jsonl_path),
                "--controls-dir", str(baselines_dir),
                "--tier-mappings", str(tmp_path / "tier-mappings.yaml"),
            ],
        )
        assert result.exit_code == 0
        json_files = list(output_dir.glob("*.json"))
        assert len(json_files) >= 1


class TestDetectCommand:
    def test_detect_finds_matches(self, runner: CliRunner, tmp_path: Path) -> None:
        """detect command finds Sigma matches and outputs results."""
        # Create a sample log file
        log_path = tmp_path / "app.log"
        log_entry = {
            "timestamp": "2026-04-20T12:00:00Z",
            "level": "WARNING",
            "event": "login_failed",
            "source_ip": "10.0.0.1",
            "user": "admin",
            "status_code": 401,
        }
        log_path.write_text(json.dumps(log_entry) + "\n")

        # Create a simple Sigma rule
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule = {
            "id": "test-rule-001",
            "title": "Test Login Failure",
            "description": "Detects login failure",
            "status": "experimental",
            "level": "medium",
            "logsource": {"category": "application"},
            "detection": {
                "selection": {"event": "login_failed"},
                "condition": "selection",
            },
            "tags": ["attack.initial_access"],
            "control_ids": ["ASVS-V2.10.1"],
        }
        import yaml
        (rules_dir / "test_rule.yml").write_text(yaml.dump(rule))

        output_jsonl = tmp_path / "findings.jsonl"

        result = runner.invoke(
            cli,
            [
                "detect", str(log_path),
                "--rules-dir", str(rules_dir),
                "--output-jsonl", str(output_jsonl),
            ],
        )
        assert result.exit_code == 0
        assert "Test Login Failure" in result.output
        assert output_jsonl.exists()
