"""Tests for SARIF universal parser."""

import json
from unittest.mock import MagicMock

import pytest

from orchestrator.parsers.sarif import is_sarif, parse_sarif

SAMPLE_SARIF = json.dumps({
    "version": "2.1.0",
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "version": "1.67.0",
                    "rules": [
                        {
                            "id": "python.lang.security.injection.sql",
                            "properties": {
                                "security-severity": "8.5",
                                "tags": ["CWE-89"],
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.injection.sql",
                    "level": "error",
                    "message": {"text": "SQL injection found"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "python.lang.security.audit.eval-used",
                    "level": "warning",
                    "message": {"text": "Use of eval()"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/utils.py"},
                                "region": {"startLine": 15},
                            }
                        }
                    ],
                },
            ],
        }
    ],
})

SAMPLE_TRIVY_SARIF = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Trivy", "version": "0.50.0", "rules": []}},
            "results": [
                {
                    "ruleId": "CVE-2024-1234",
                    "level": "error",
                    "message": {"text": "Critical vulnerability in openssl"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}, "region": {"startLine": 1}}}],
                    "properties": {"package": "openssl", "installedVersion": "3.1.2", "fixedVersion": "3.1.5"},
                }
            ],
        }
    ],
})


@pytest.fixture
def mapper() -> MagicMock:
    m = MagicMock()
    m.map_finding.return_value = []
    return m


class TestSarifParser:
    def test_parse_returns_findings(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_SARIF, mapper)
        assert len(findings) == 2

    def test_source_is_tool_name(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_SARIF, mapper)
        assert all(f.source == "semgrep" for f in findings)

    def test_rule_id_preserved(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_SARIF, mapper)
        assert findings[0].rule_id == "python.lang.security.injection.sql"

    def test_severity_from_security_severity(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_SARIF, mapper)
        # security-severity: 8.5 → high
        assert findings[0].severity == "high"

    def test_file_and_line(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_SARIF, mapper)
        assert findings[0].file == "src/app.py"
        assert findings[0].line == 42

    def test_cwe_in_message(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_SARIF, mapper)
        assert "CWE-89" in findings[0].message

    def test_trivy_sarif(self, mapper: MagicMock) -> None:
        findings = parse_sarif(SAMPLE_TRIVY_SARIF, mapper)
        assert len(findings) == 1
        assert findings[0].source == "trivy"
        assert findings[0].package == "openssl"
        assert findings[0].installed_version == "3.1.2"
        assert findings[0].fixed_version == "3.1.5"

    def test_invalid_json(self, mapper: MagicMock) -> None:
        findings = parse_sarif("not json", mapper)
        assert findings == []

    def test_empty_runs(self, mapper: MagicMock) -> None:
        findings = parse_sarif('{"version":"2.1.0","runs":[]}', mapper)
        assert findings == []

    def test_maps_controls(self, mapper: MagicMock) -> None:
        parse_sarif(SAMPLE_SARIF, mapper)
        mapper.map_finding.assert_called()


class TestIsSarif:
    def test_valid_sarif(self) -> None:
        assert is_sarif(SAMPLE_SARIF) is True

    def test_not_sarif(self) -> None:
        assert is_sarif('{"results": []}') is False

    def test_invalid_json(self) -> None:
        assert is_sarif("not json") is False
