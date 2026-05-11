"""Tests for import-framework CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from orchestrator.cli import cli

FIXTURES = Path(__file__).parent.parent / "fixtures" / "oscal"


class TestImportFrameworkHelp:
    """test_import_framework_help — command help 출력."""

    def test_import_framework_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["import-framework", "--help"])
        assert result.exit_code == 0
        assert "Import a compliance framework" in result.output
        assert "--framework-id" in result.output
        assert "--format" in result.output
        assert "--suggest-scanners" in result.output
        assert "--tiers" in result.output


class TestImportOscalCreatesYaml:
    """test_import_oscal_creates_yaml — OSCAL fixture -> YAML 파일 생성."""

    def test_import_oscal_creates_yaml(self, tmp_path: Path) -> None:
        output = tmp_path / "cmmc-test.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "import-framework",
            str(FIXTURES / "nist-800-53-sample.json"),
            "--framework-id", "cmmc-test",
            "--format", "oscal",
            "--output", str(output),
            "--suggest-scanners",
        ])
        assert result.exit_code == 0, result.output
        assert output.exists()

        data = yaml.safe_load(output.read_text())
        assert "controls" in data
        assert len(data["controls"]) == 2


class TestImportWithSuggestions:
    """test_import_with_suggestions — YAML에 제안된 verification_methods 포함."""

    def test_import_with_suggestions(self, tmp_path: Path) -> None:
        output = tmp_path / "suggested.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "import-framework",
            str(FIXTURES / "nist-800-53-sample.json"),
            "--framework-id", "suggest-test",
            "--output", str(output),
            "--suggest-scanners",
        ])
        assert result.exit_code == 0, result.output

        data = yaml.safe_load(output.read_text())
        # At least one control should have suggested verification_methods
        # (ac-1 has "access control" in title -> should match keyword)
        has_suggestions = any(
            len(entry["control"].get("verification_methods", [])) > 0
            for entry in data["controls"]
        )
        assert has_suggestions

        # Check that suggested methods have status "suggested — review required"
        for entry in data["controls"]:
            for vm in entry["control"].get("verification_methods", []):
                assert vm.get("status") == "suggested — review required"


class TestImportWithoutSuggestions:
    """test_import_without_suggestions — --suggest-scanners=false -> verification_methods: []."""

    def test_import_without_suggestions(self, tmp_path: Path) -> None:
        output = tmp_path / "no-suggest.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "import-framework",
            str(FIXTURES / "nist-800-53-sample.json"),
            "--framework-id", "no-suggest-test",
            "--output", str(output),
            "--no-suggest-scanners",
        ])
        assert result.exit_code == 0, result.output

        data = yaml.safe_load(output.read_text())
        for entry in data["controls"]:
            assert entry["control"]["verification_methods"] == []


class TestImportPrintsSummary:
    """test_import_prints_summary — 출력에 imported/suggested/unmapped 카운트 포함."""

    def test_import_prints_summary(self, tmp_path: Path) -> None:
        output = tmp_path / "summary.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "import-framework",
            str(FIXTURES / "nist-800-53-sample.json"),
            "--framework-id", "summary-test",
            "--output", str(output),
        ])
        assert result.exit_code == 0, result.output

        # Check summary output
        assert "Parsing" in result.output
        assert "Controls found:" in result.output
        assert "Generating baseline" in result.output
        assert "Baseline generated" in result.output
        assert "Scanner mappings are SUGGESTIONS" in result.output or "scanner" in result.output.lower()


class TestImportFromUrl:
    """test_import_from_url — URL mock -> 파싱 성공."""

    @patch("orchestrator.importer.oscal.urlopen")
    def test_import_from_url(self, mock_urlopen: MagicMock, tmp_path: Path) -> None:
        sample_path = FIXTURES / "nist-800-53-sample.json"
        sample_data = sample_path.read_bytes()

        mock_response = MagicMock()
        mock_response.read.return_value = sample_data
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        output = tmp_path / "from-url.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "import-framework",
            "https://example.com/catalog.json",
            "--framework-id", "url-test",
            "--output", str(output),
        ])
        assert result.exit_code == 0, result.output
        assert output.exists()
        mock_urlopen.assert_called_once()
