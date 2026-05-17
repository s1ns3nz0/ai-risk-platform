"""Regressions for the T1/T2/T3 red-team findings.

T1: int(None) crash on null StartLine in misconfigurations/secrets.
T2: Trivy secrets must count toward the gate's secrets_count predicate.
T3: Trivy vulns inherit grype severity-threshold mapping; secrets inherit
    gitleaks rule-agnostic mapping.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from orchestrator.scanners.trivy import TrivyScanner
from orchestrator.types import Finding, is_secret_finding


def _mapper_with_mappings(grype_returns=None, gitleaks_returns=None, trivy_returns=None):
    """Mapper that returns scanner-specific control lists so we can assert
    Trivy is routing through the right key."""
    grype_returns = grype_returns or ["CTRL-SCA-1"]
    gitleaks_returns = gitleaks_returns or ["CTRL-SECRETS-1"]
    trivy_returns = trivy_returns or []
    m = MagicMock()

    def _map(source, rule_id, severity=None):
        if source == "grype":
            return list(grype_returns)
        if source == "gitleaks":
            return list(gitleaks_returns)
        if source == "trivy":
            return list(trivy_returns)
        return []

    m.map_finding.side_effect = _map
    return m


# ---- T1: defensive null handling ----


def test_t1_null_startline_misconfig_does_not_crash():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "Dockerfile",
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS001",
                        "Title": "no USER",
                        "Severity": "HIGH",
                        "CauseMetadata": {"StartLine": None},  # Trivy can emit null
                    }
                ],
            }
        ],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    assert len(findings) == 1
    assert findings[0].line == 0  # null → 0, no exception


def test_t1_missing_cause_metadata_does_not_crash():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "Dockerfile",
        "Results": [{
            "Target": "Dockerfile",
            "Misconfigurations": [
                {"ID": "DS001", "Title": "x", "Severity": "MEDIUM"},
            ],
        }],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    assert findings[0].line == 0


def test_t1_null_startline_secret_does_not_crash():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [{
            "Target": ".env",
            "Secrets": [
                {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": None},
            ],
        }],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    assert len(findings) == 1
    assert findings[0].line == 0


# ---- T3: control mapping uses grype for vulns, gitleaks for secrets ----


def test_t3_vulns_map_via_grype():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "app",
        "Results": [{
            "Target": "app",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-1", "PkgName": "p", "Severity": "HIGH"},
            ],
        }],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    # Mapper was hit with source="grype" — control_ids match the grype mapping.
    assert findings[0].control_ids == ["CTRL-SCA-1"]


def test_t3_secrets_map_via_gitleaks():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [{
            "Target": ".env",
            "Secrets": [
                {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": 3},
            ],
        }],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    assert findings[0].control_ids == ["CTRL-SECRETS-1"]


# ---- T2: secret prefix + helper ----


def test_t2_secrets_get_prefix():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [{
            "Target": ".env",
            "Secrets": [
                {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": 3},
            ],
        }],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    assert findings[0].rule_id == "secret-aws-access-key-id"
    # Source preserved for audit trail.
    assert findings[0].source == "trivy"


def test_t2_double_prefix_is_idempotent():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [{
            "Target": ".env",
            "Secrets": [
                {"RuleID": "secret-already-prefixed", "Severity": "HIGH", "StartLine": 1},
            ],
        }],
    })
    findings = TrivyScanner(_mapper_with_mappings()).parse_output(raw)
    assert findings[0].rule_id == "secret-already-prefixed"


def test_t2_is_secret_helper_recognizes_both():
    gitleaks = Finding(
        source="gitleaks", rule_id="aws-access-key", severity="critical",
        file="x", line=1, message="m", control_ids=[], product="p",
    )
    trivy_secret = Finding(
        source="trivy", rule_id="secret-github-pat", severity="high",
        file="x", line=1, message="m", control_ids=[], product="p",
    )
    trivy_vuln = Finding(
        source="trivy", rule_id="CVE-2024-1", severity="high",
        file="x", line=1, message="m", control_ids=[], product="p",
    )
    assert is_secret_finding(gitleaks) is True
    assert is_secret_finding(trivy_secret) is True
    assert is_secret_finding(trivy_vuln) is False
