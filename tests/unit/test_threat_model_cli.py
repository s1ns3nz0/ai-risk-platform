"""Tests for threat-model CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from orchestrator.cli import cli
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.scanners.sbom import SbomResult
from orchestrator.types import Finding


def _make_sbom_result() -> SbomResult:
    return SbomResult(
        sbom_path="/tmp/sbom.cdx.json",
        format="cyclonedx-json",
        components_count=132,
        raw_sbom={
            "components": [
                {"name": f"pkg-{i}", "version": "1.0.0", "type": "library"}
                for i in range(132)
            ]
        },
    )


def _make_grype_findings() -> list[Finding]:
    return [
        Finding(
            source="grype",
            rule_id="CVE-2022-29217",
            severity="critical",
            file="requirements.txt",
            line=0,
            message="JWT algorithm confusion",
            control_ids=["ASVS-V3.5.3", "PCI-DSS-8.3.1"],
            product="",
            package="PyJWT",
            installed_version="1.7.1",
            fixed_version="2.4.0",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-0001",
            severity="high",
            file="requirements.txt",
            line=0,
            message="Some vuln",
            control_ids=["PCI-DSS-6.3.1"],
            product="",
            package="requests",
            installed_version="2.25.0",
            fixed_version="2.28.0",
        ),
    ]


def _make_enriched_vulns() -> list[EnrichedVulnerability]:
    return [
        EnrichedVulnerability(
            cve_id="CVE-2022-29217",
            severity="critical",
            epss_score=0.67,
            epss_percentile=0.97,
            package="PyJWT",
            installed_version="1.7.1",
            fixed_version="2.4.0",
            file_path="requirements.txt",
            control_ids=["ASVS-V3.5.3", "PCI-DSS-8.3.1"],
            priority="critical",
            product_context="payment-api, PCI scope",
            data_classification=["PCI", "PII-financial"],
        ),
        EnrichedVulnerability(
            cve_id="CVE-2023-0001",
            severity="high",
            epss_score=0.15,
            epss_percentile=0.85,
            package="requests",
            installed_version="2.25.0",
            fixed_version="2.28.0",
            file_path="requirements.txt",
            control_ids=["PCI-DSS-6.3.1"],
            priority="high",
            product_context="payment-api, PCI scope",
            data_classification=["PCI", "PII-financial"],
        ),
    ]


class TestThreatModelHelp:
    def test_threat_model_help(self) -> None:
        """command help 출력."""
        runner = CliRunner()
        result = runner.invoke(cli, ["threat-model", "--help"])
        assert result.exit_code == 0
        assert "threat model" in result.output.lower() or "threat-model" in result.output.lower()
        assert "--product" in result.output
        assert "--output" in result.output


_PATCH_SBOM = "orchestrator.scanners.sbom.SbomGenerator"
_PATCH_GRYPE = "orchestrator.scanners.grype.GrypeScanner"
_PATCH_EPSS = "orchestrator.intelligence.epss.EpssClient"
_PATCH_ENRICHER = "orchestrator.intelligence.enricher.VulnerabilityEnricher"


def _setup_mocks(
    mock_sbom_cls: MagicMock,
    mock_grype_cls: MagicMock,
    mock_enricher_cls: MagicMock,
) -> None:
    mock_sbom_cls.return_value.generate.return_value = _make_sbom_result()
    mock_grype_cls.return_value.scan.return_value = _make_grype_findings()
    mock_enricher_cls.return_value.enrich.return_value = _make_enriched_vulns()
    mock_enricher_cls.return_value.sort_by_priority.return_value = _make_enriched_vulns()


class TestThreatModelProducesYaml:
    @patch(_PATCH_SBOM)
    @patch(_PATCH_GRYPE)
    @patch(_PATCH_EPSS)
    @patch(_PATCH_ENRICHER)
    def test_threat_model_produces_yaml(
        self,
        mock_enricher_cls: MagicMock,
        mock_epss_cls: MagicMock,
        mock_grype_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """output 디렉토리에 YAML 생성."""
        _setup_mocks(mock_sbom_cls, mock_grype_cls, mock_enricher_cls)

        output_dir = str(tmp_path / "output")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["threat-model", "./sample-app", "--product", "payment-api", "--output", output_dir],
        )

        assert result.exit_code == 0, result.output
        yaml_path = tmp_path / "output" / "threat-model-payment-api.yaml"
        assert yaml_path.exists(), f"Expected {yaml_path} to exist. Output: {result.output}"


class TestThreatModelContainsScenarios:
    @patch(_PATCH_SBOM)
    @patch(_PATCH_GRYPE)
    @patch(_PATCH_EPSS)
    @patch(_PATCH_ENRICHER)
    def test_threat_model_contains_scenarios(
        self,
        mock_enricher_cls: MagicMock,
        mock_epss_cls: MagicMock,
        mock_grype_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """위협 시나리오 포함."""
        _setup_mocks(mock_sbom_cls, mock_grype_cls, mock_enricher_cls)

        output_dir = str(tmp_path / "output")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["threat-model", "./sample-app", "--product", "payment-api", "--output", output_dir],
        )

        assert result.exit_code == 0, result.output
        yaml_path = tmp_path / "output" / "threat-model-payment-api.yaml"
        parsed = yaml.safe_load(yaml_path.read_text())

        assert "threat_model" in parsed
        tm = parsed["threat_model"]
        assert "threat_scenarios" in tm
        assert len(tm["threat_scenarios"]) >= 1
        scenario = tm["threat_scenarios"][0]
        assert "mitre_technique" in scenario
        assert "affected_controls" in scenario


class TestThreatModelContainsControlsGap:
    @patch(_PATCH_SBOM)
    @patch(_PATCH_GRYPE)
    @patch(_PATCH_EPSS)
    @patch(_PATCH_ENRICHER)
    def test_threat_model_contains_controls_gap(
        self,
        mock_enricher_cls: MagicMock,
        mock_epss_cls: MagicMock,
        mock_grype_cls: MagicMock,
        mock_sbom_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """컨트롤 gap 분석 포함."""
        _setup_mocks(mock_sbom_cls, mock_grype_cls, mock_enricher_cls)

        output_dir = str(tmp_path / "output")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["threat-model", "./sample-app", "--product", "payment-api", "--output", output_dir],
        )

        assert result.exit_code == 0, result.output
        assert "gap" in result.output.lower() or "Gap" in result.output

        yaml_path = tmp_path / "output" / "threat-model-payment-api.yaml"
        parsed = yaml.safe_load(yaml_path.read_text())
        tm = parsed["threat_model"]
        assert "controls_gap" in tm
