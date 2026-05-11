"""Tests for ScannerSuggester — keyword-based scanner mapping suggestions."""

from __future__ import annotations

from pathlib import Path

import yaml

from orchestrator.importer.oscal import ImportedControl
from orchestrator.importer.suggest import ScannerSuggester


def _make_control(
    title: str = "Test Control",
    description: str = "",
    control_id: str = "TEST-1",
    framework: str = "test-fw",
) -> ImportedControl:
    return ImportedControl(
        id=control_id,
        title=title,
        description=description,
        framework=framework,
    )


class TestSuggestAccessControl:
    """test_access_control_suggests_checkov — 'access control' → checkov IAM checks."""

    def test_access_control_suggests_checkov(self) -> None:
        ctrl = _make_control(title="Access Control Policy", description="Define access control.")
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        scanners = [s["scanner"] for s in suggestions]
        assert "checkov" in scanners

        checkov = next(s for s in suggestions if s["scanner"] == "checkov")
        assert "check_ids" in checkov


class TestSuggestEncryption:
    """test_encryption_suggests_checkov_and_semgrep — 'encrypt' → checkov + semgrep crypto."""

    def test_encryption_suggests_checkov_and_semgrep(self) -> None:
        ctrl = _make_control(
            title="Encrypt Data at Rest",
            description="All data must be encrypted using strong cryptography.",
        )
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        scanners = [s["scanner"] for s in suggestions]
        assert "checkov" in scanners
        assert "semgrep" in scanners


class TestSuggestVulnerability:
    """test_vulnerability_suggests_grype — 'vulnerability' → grype."""

    def test_vulnerability_suggests_grype(self) -> None:
        ctrl = _make_control(
            title="Vulnerability Management",
            description="Identify and remediate vulnerabilities.",
        )
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        scanners = [s["scanner"] for s in suggestions]
        assert "grype" in scanners


class TestSuggestLogging:
    """test_logging_suggests_sigma — 'audit log' → sigma."""

    def test_logging_suggests_sigma(self) -> None:
        ctrl = _make_control(
            title="Audit Logging",
            description="Enable audit log for all access.",
        )
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        scanners = [s["scanner"] for s in suggestions]
        assert "sigma" in scanners


class TestNoKeywordMatch:
    """test_no_keyword_match_returns_empty — 'physical security' → []."""

    def test_no_keyword_match_returns_empty(self) -> None:
        ctrl = _make_control(
            title="Physical Security",
            description="Ensure physical perimeter protection for data centers.",
        )
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        assert suggestions == []


class TestMultipleKeywordsMerged:
    """test_multiple_keywords_merged — 'authentication and encryption' → gitleaks + checkov + semgrep."""

    def test_multiple_keywords_merged(self) -> None:
        ctrl = _make_control(
            title="Authentication and Encryption Requirements",
            description="Ensure strong authentication and encryption.",
        )
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        scanners = [s["scanner"] for s in suggestions]
        assert "gitleaks" in scanners
        assert "checkov" in scanners
        assert "semgrep" in scanners

    def test_no_duplicate_scanners(self) -> None:
        """동일 scanner가 중복 제안되지 않는다 (동일 check_ids/rules는 병합)."""
        ctrl = _make_control(
            title="Authentication and Password Policy",
            description="Manage passwords and credentials.",
        )
        suggester = ScannerSuggester()
        suggestions = suggester.suggest(ctrl)

        # Each scanner appears at most once
        scanners = [s["scanner"] for s in suggestions]
        assert len(scanners) == len(set(scanners))


class TestApplySuggestionsUpdatesYaml:
    """test_apply_suggestions_updates_yaml — YAML 파일에 제안 적용."""

    def test_apply_suggestions_updates_yaml(self, tmp_path: Path) -> None:
        controls = [
            _make_control(
                control_id="AC-1",
                title="Access Control Policy",
                description="Define access control.",
            ),
            _make_control(
                control_id="PHY-1",
                title="Physical Security",
                description="Physical perimeter protection.",
            ),
        ]
        output = tmp_path / "baseline.yaml"
        suggester = ScannerSuggester()
        suggested, no_suggestion = suggester.apply_suggestions(controls, str(output))

        assert suggested == 1
        assert no_suggestion == 1

        data = yaml.safe_load(output.read_text())
        assert "controls" in data

        ac1 = data["controls"][0]["control"]
        assert ac1["id"] == "AC-1"
        assert len(ac1["verification_methods"]) > 0
        # All suggestions are labelled
        for vm in ac1["verification_methods"]:
            assert vm.get("status") == "suggested — review required"

        phy1 = data["controls"][1]["control"]
        assert phy1["id"] == "PHY-1"
        assert phy1["verification_methods"] == []

    def test_suggestions_include_status_label(self, tmp_path: Path) -> None:
        """모든 제안에 'suggested — review required' 라벨이 있다."""
        controls = [
            _make_control(
                control_id="VM-1",
                title="Vulnerability Scanning",
                description="Scan for vulnerabilities regularly.",
            ),
        ]
        output = tmp_path / "baseline.yaml"
        suggester = ScannerSuggester()
        suggester.apply_suggestions(controls, str(output))

        data = yaml.safe_load(output.read_text())
        ctrl = data["controls"][0]["control"]
        for vm in ctrl["verification_methods"]:
            assert vm["status"] == "suggested — review required"
