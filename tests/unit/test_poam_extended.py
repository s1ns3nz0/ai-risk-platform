"""Tests for the extended POA&M data model (nested ticket/weakness/source/
impact/lifecycle/remediation/delay/risk_acceptance/verification fields).

The customer schema spec lists every field and who fills it. These tests
pin the auto-populated subset; pipeline-filled fields stay empty until
the operator POSTs them.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

import pytest

from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.rmf.poam import (
    POAMGenerator,
    POAMItem,
    POAMTicket,
    POAMWeakness,
    POAMSource,
    POAMImpact,
    POAMLifecycle,
    POAMRemediation,
    POAMDelay,
    POAMRiskAcceptance,
    POAMVerification,
)
from orchestrator.types import Finding, ProductManifest


def _make_manifest() -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="QR payment service",
        data_classification=["PCI", "PII-financial"],
        jurisdiction=["US"],
        deployment={"cloud": "AWS"},
        impact_levels={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
    )


def _grype_cve_finding() -> Finding:
    return Finding(
        source="grype",
        rule_id="CVE-2026-1234",
        severity="high",
        file="pom.xml",
        line=0,
        message="Remote code execution in spring-core",
        control_ids=["NIST-SP-800-53-RA-5", "NIST-SP-800-53-SI-2"],
        product="payment-api",
        package="org.springframework:spring-core",
        installed_version="6.1.6",
        fixed_version="6.1.7",
        cvss_score=8.1,
    )


# ---------------- weakness ----------------


def test_weakness_carries_cve_cvss_epss_package():
    enriched = [
        EnrichedVulnerability(
            cve_id="CVE-2026-1234",
            severity="high",
            epss_score=0.034,
            epss_percentile=0.5,
            package="spring-core",
            installed_version="6.1.6",
            fixed_version="6.1.7",
            file_path="pom.xml",
            control_ids=[],
            priority="high",
            product_context="",
        ),
    ]
    items = POAMGenerator().generate(
        findings=[_grype_cve_finding()],
        manifest=_make_manifest(),
        enriched_vulns=enriched,
    )
    assert len(items) == 1
    w = items[0].weakness_detail
    assert w.cve_id == "CVE-2026-1234"
    assert w.cvss_score == 8.1
    assert w.epss_score == 0.034
    assert w.package == "org.springframework:spring-core"
    assert w.severity == "high"
    assert w.supply_chain is True  # SCA + package present
    assert w.description  # static template populates this


def test_weakness_non_cve_finding_has_no_cve_id():
    semgrep = Finding(
        source="semgrep", rule_id="python.lang.sql-injection", severity="high",
        file="api/db.py", line=42, message="SQLi", control_ids=[],
        product="payment-api",
    )
    items = POAMGenerator().generate(findings=[semgrep], manifest=_make_manifest())
    w = items[0].weakness_detail
    assert w.cve_id == ""
    assert w.supply_chain is False
    assert w.package == ""


# ---------------- source ----------------


def test_source_scan_type_derived_from_scanner():
    cases = [
        ("grype", "SCA"),
        ("trivy", "SCA"),
        ("semgrep", "SAST"),
        ("gitleaks", "Secret"),
        ("checkov", "IaC"),
        ("zap", "DAST"),
        ("spotbugs", "SAST"),
    ]
    for scanner, expected in cases:
        f = Finding(source=scanner, rule_id="X", severity="high", file="",
                   line=0, message="", control_ids=[], product="p")
        items = POAMGenerator().generate(findings=[f], manifest=_make_manifest())
        assert items[0].source_detail.scan_type == expected, scanner


def test_source_phase_derived_from_trigger():
    f = _grype_cve_finding()
    for trigger, expected in [("pre_merge", "BUILD"), ("pre_deploy", "DEPLOY"), ("periodic", "OPERATE")]:
        items = POAMGenerator().generate(findings=[f], manifest=_make_manifest(), trigger=trigger)
        assert items[0].source_detail.phase == expected


def test_source_framework_refs_from_control_ids():
    items = POAMGenerator().generate(findings=[_grype_cve_finding()], manifest=_make_manifest())
    assert items[0].source_detail.framework_refs == [
        "NIST-SP-800-53-RA-5", "NIST-SP-800-53-SI-2",
    ]


def test_source_evidence_url_propagated():
    url = "https://github.com/acme/svc/actions/runs/42"
    items = POAMGenerator().generate(
        findings=[_grype_cve_finding()], manifest=_make_manifest(), evidence_url=url,
    )
    assert items[0].source_detail.evidence_url == url


# ---------------- impact ----------------


def test_impact_from_manifest():
    items = POAMGenerator().generate(findings=[_grype_cve_finding()], manifest=_make_manifest())
    impact = items[0].impact
    assert impact.affected_asset == "payment-api"
    assert impact.cia == {"confidentiality": "high", "integrity": "high", "availability": "moderate"}
    assert impact.data_classification == ["PCI", "PII-financial"]
    assert impact.business_impact  # static template populates


def test_impact_empty_when_no_manifest():
    items = POAMGenerator().generate(findings=[_grype_cve_finding()])
    assert items[0].impact.affected_asset == ""
    assert items[0].impact.cia == {}


# ---------------- lifecycle ----------------


def test_lifecycle_dates_are_iso_and_consistent():
    items = POAMGenerator().generate(findings=[_grype_cve_finding()], manifest=_make_manifest())
    lc = items[0].lifecycle
    # Discovered-at must parse as ISO and be very recent.
    discovered = datetime.fromisoformat(lc.discovered_at)
    assert (datetime.now(timezone.utc) - discovered).total_seconds() < 5
    # high severity → 30-day SLA in the existing _DEADLINE_DAYS table.
    assert lc.sla_days == 30
    # due_date matches scheduled_completion (legacy field).
    assert lc.due_date == items[0].scheduled_completion
    assert lc.closed_at is None


# ---------------- remediation ----------------


def test_remediation_upgrade_plan_when_fixed_version_present():
    items = POAMGenerator().generate(findings=[_grype_cve_finding()], manifest=_make_manifest())
    r = items[0].remediation
    assert "6.1.7" in r.plan
    assert "spring-core" in r.plan
    assert r.owner  # responsible auto-assigned
    assert r.resources_required


def test_remediation_vendor_dependency_when_no_fix():
    f = Finding(
        source="grype", rule_id="CVE-2026-9999", severity="critical",
        file="", line=0, message="", control_ids=[], product="p",
        package="zerodaylib", installed_version="1.0", fixed_version="",
    )
    items = POAMGenerator().generate(findings=[f], manifest=_make_manifest())
    assert "zerodaylib" in items[0].remediation.vendor_dependency


def test_remediation_secret_rotation_message():
    f = Finding(
        source="gitleaks", rule_id="aws-access-key", severity="critical",
        file=".env", line=3, message="leak", control_ids=[], product="p",
    )
    items = POAMGenerator().generate(findings=[f], manifest=_make_manifest())
    plan = items[0].remediation.plan.lower()
    assert "rotate" in plan


# ---------------- manual fields default empty ----------------


def test_manual_fields_default_empty():
    """delay/risk_acceptance/verification (except auto-marker) must be empty
    by default — only the operator/AO can fill them via future endpoints."""
    items = POAMGenerator().generate(findings=[_grype_cve_finding()], manifest=_make_manifest())
    item = items[0]
    assert asdict(item.delay) == {"justification": "", "approved_by": ""}
    assert asdict(item.risk_acceptance) == {
        "accepted_by": "", "justification": "", "compensating_controls": [],
    }
    assert item.verification.verified_by == "automated"
    assert item.verification.verified_at == ""
    assert asdict(item.ticket) == {"id": "", "url": ""}


# ---------------- back-compat ----------------


def test_legacy_top_level_fields_still_match_nested():
    items = POAMGenerator().generate(findings=[_grype_cve_finding()], manifest=_make_manifest())
    item = items[0]
    # The legacy fields must match the canonical nested ones (callers that
    # haven't migrated still read the right values).
    assert item.source == item.source_detail.scanner
    assert item.finding_id == item.source_detail.finding_id
    assert item.scheduled_completion == item.lifecycle.due_date
    assert item.responsible == item.remediation.owner


# ---------------- CVSS extraction ----------------


def test_grype_parser_extracts_cvss():
    """Sanity check the upstream change that surfaces cvss_score onto Finding."""
    from unittest.mock import MagicMock
    from orchestrator.scanners.grype import GrypeScanner

    mapper = MagicMock(); mapper.map_finding.return_value = []
    grype_json = """{
        "matches": [{
            "vulnerability": {
                "id": "CVE-2026-1234",
                "severity": "High",
                "description": "RCE",
                "cvss": [{"version": "3.1", "metrics": {"baseScore": 8.1}}]
            },
            "artifact": {"name": "spring-core", "version": "6.1.6", "locations": []}
        }],
        "descriptor": {"name": "grype"}
    }"""
    findings = GrypeScanner(mapper).parse_output(grype_json)
    assert findings[0].cvss_score == 8.1


def test_trivy_parser_extracts_cvss():
    from unittest.mock import MagicMock
    from orchestrator.scanners.trivy import TrivyScanner

    mapper = MagicMock(); mapper.map_finding.return_value = []
    trivy_json = """{
        "SchemaVersion": 2,
        "ArtifactName": "img",
        "Results": [{
            "Target": "img",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-1234",
                "PkgName": "spring-core",
                "Severity": "HIGH",
                "CVSS": {"nvd": {"V3Score": 8.1, "V3Vector": "CVSS:3.1/..."}}
            }]
        }]
    }"""
    findings = TrivyScanner(mapper).parse_output(trivy_json)
    assert findings[0].cvss_score == 8.1
