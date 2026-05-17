"""Unit tests for the Trivy native JSON parser."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from orchestrator.scanners.trivy import TrivyScanner


def _mapper():
    m = MagicMock()
    m.map_finding.return_value = []
    return m


def test_parse_vulnerabilities():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "app:1.0",
        "Results": [
            {
                "Target": "image:1.0 (alpine 3.18)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1",
                        "PkgName": "libssl",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "CRITICAL",
                        "Title": "libssl bug",
                    }
                ],
            }
        ],
    })
    findings = TrivyScanner(_mapper()).parse_output(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "trivy"
    assert f.rule_id == "CVE-2024-1"
    assert f.severity == "critical"
    assert f.package == "libssl"
    assert f.installed_version == "1.0"
    assert f.fixed_version == "1.1"


def test_parse_misconfigurations_carries_line():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "Dockerfile",
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Image user should not be root",
                        "Severity": "HIGH",
                        "CauseMetadata": {"StartLine": 7},
                    }
                ],
            }
        ],
    })
    findings = TrivyScanner(_mapper()).parse_output(raw)
    assert len(findings) == 1
    assert findings[0].rule_id == "DS002"
    assert findings[0].severity == "high"
    assert findings[0].line == 7


def test_parse_secrets():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": ".env",
        "Results": [
            {
                "Target": ".env",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Severity": "CRITICAL",
                        "StartLine": 3,
                        "Title": "AWS Access Key ID",
                    }
                ],
            }
        ],
    })
    findings = TrivyScanner(_mapper()).parse_output(raw)
    assert len(findings) == 1
    # Prefixed so the gate's secret predicate catches it regardless of source.
    assert findings[0].rule_id == "secret-aws-access-key-id"
    assert findings[0].severity == "critical"


def test_unknown_severity_falls_back_to_info():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-X", "Severity": "WEIRD"}
                ],
            }
        ],
    })
    findings = TrivyScanner(_mapper()).parse_output(raw)
    assert findings[0].severity == "info"


def test_invalid_json_returns_empty():
    assert TrivyScanner(_mapper()).parse_output("not json") == []


def test_missing_results_returns_empty():
    raw = json.dumps({"SchemaVersion": 2, "ArtifactName": "x"})
    assert TrivyScanner(_mapper()).parse_output(raw) == []


def test_skips_malformed_vuln_entries():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [
            {
                "Target": "x",
                "Vulnerabilities": [
                    "not-a-dict",
                    {"VulnerabilityID": ""},  # empty rule id skipped
                    {"VulnerabilityID": "CVE-OK", "Severity": "LOW"},
                ],
            }
        ],
    })
    findings = TrivyScanner(_mapper()).parse_output(raw)
    assert len(findings) == 1
    assert findings[0].rule_id == "CVE-OK"
