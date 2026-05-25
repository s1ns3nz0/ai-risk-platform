"""Tests for CWE extraction, SBOM correlation, and cross-run reconciliation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from orchestrator.persistence import AssessmentStore, AssessmentRecord
from orchestrator.rmf.poam import POAMGenerator, fingerprint_for_finding
from orchestrator.rmf.reconciler import reconcile_against_previous
from orchestrator.rmf.sbom_correlator import SbomCorrelator
from orchestrator.scanners.grype import GrypeScanner
from orchestrator.scanners.trivy import TrivyScanner
from orchestrator.types import Finding, ProductManifest


def _mapper():
    m = MagicMock()
    m.map_finding.return_value = []
    return m


def _manifest() -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="x",
        data_classification=["PCI"],
        jurisdiction=["US"],
        deployment={"cloud": "AWS"},
        impact_levels={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
    )


# ---------------- CWE extraction ----------------


def test_grype_parser_extracts_cwe_from_vulnerability():
    raw = json.dumps({
        "matches": [{
            "vulnerability": {
                "id": "CVE-2026-1",
                "severity": "High",
                "cwes": ["CWE-79", "CWE-89"],
            },
            "artifact": {"name": "pkg", "version": "1.0", "locations": []},
        }],
        "descriptor": {"name": "grype"},
    })
    findings = GrypeScanner(_mapper()).parse_output(raw)
    assert findings[0].cwe_ids == ["CWE-79", "CWE-89"]


def test_grype_parser_extracts_cwe_from_related_when_main_missing():
    raw = json.dumps({
        "matches": [{
            "vulnerability": {"id": "GHSA-x", "severity": "high"},
            "relatedVulnerabilities": [
                {"id": "CVE-2026-2", "cwes": ["CWE-22"]},
            ],
            "artifact": {"name": "pkg", "version": "1.0", "locations": []},
        }],
        "descriptor": {"name": "grype"},
    })
    findings = GrypeScanner(_mapper()).parse_output(raw)
    assert findings[0].cwe_ids == ["CWE-22"]


def test_trivy_parser_extracts_cwe_ids():
    raw = json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [{
            "Target": "x",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-1",
                "PkgName": "p",
                "Severity": "HIGH",
                "CweIDs": ["CWE-79"],
            }],
        }],
    })
    findings = TrivyScanner(_mapper()).parse_output(raw)
    assert findings[0].cwe_ids == ["CWE-79"]


def test_poam_weakness_carries_cwe_primary_and_list():
    f = Finding(
        source="trivy", rule_id="CVE-2026-1", severity="high", file="", line=0,
        message="m", control_ids=[], product="p", package="pkg",
        installed_version="1.0", cwe_ids=["CWE-79", "CWE-89"],
    )
    items = POAMGenerator().generate(findings=[f], manifest=_manifest())
    w = items[0].weakness_detail
    assert w.cwe_id == "CWE-79"     # primary = first entry
    assert w.cwe_ids == ["CWE-79", "CWE-89"]


def test_poam_weakness_cwe_empty_when_scanner_omits():
    f = Finding(
        source="grype", rule_id="CVE-2026-1", severity="high", file="", line=0,
        message="m", control_ids=[], product="p", package="pkg",
    )
    items = POAMGenerator().generate(findings=[f], manifest=_manifest())
    assert items[0].weakness_detail.cwe_id == ""
    assert items[0].weakness_detail.cwe_ids == []


# ---------------- SBOM correlation ----------------


_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "spring-core",
            "version": "6.1.6",
            "group": "org.springframework",
            "purl": "pkg:maven/org.springframework/spring-core@6.1.6",
            "bom-ref": "pkg:maven/org.springframework/spring-core@6.1.6",
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "bom-ref": "pkg:npm/lodash@4.17.21",
        },
    ],
}


def test_sbom_correlator_matches_maven_coordinates():
    c = SbomCorrelator(_SBOM)
    ref = c.correlate("org.springframework:spring-core", "6.1.6")
    assert ref == "bom.json#components/pkg:maven/org.springframework/spring-core@6.1.6"


def test_sbom_correlator_matches_purl_directly():
    c = SbomCorrelator(_SBOM)
    ref = c.correlate("pkg:npm/lodash@4.17.21", "")
    assert ref == "bom.json#components/pkg:npm/lodash@4.17.21"


def test_sbom_correlator_falls_back_to_name_only():
    c = SbomCorrelator(_SBOM)
    ref = c.correlate("lodash", "")
    assert "lodash" in ref


def test_sbom_correlator_returns_empty_when_no_match():
    c = SbomCorrelator(_SBOM)
    assert c.correlate("totally-unknown-pkg", "9.9.9") == ""


def test_sbom_correlator_handles_missing_sbom():
    c = SbomCorrelator(None)
    assert c.correlate("any", "1.0") == ""


def test_poam_uses_sbom_correlation_when_present():
    f = Finding(
        source="grype", rule_id="CVE-2026-1", severity="high", file="", line=0,
        message="", control_ids=[], product="p",
        package="org.springframework:spring-core", installed_version="6.1.6",
    )
    items = POAMGenerator().generate(findings=[f], manifest=_manifest(), sbom=_SBOM)
    assert items[0].source_detail.sbom_ref.endswith("spring-core@6.1.6")


def test_poam_sbom_ref_empty_without_sbom():
    f = Finding(
        source="grype", rule_id="CVE-2026-1", severity="high", file="", line=0,
        message="", control_ids=[], product="p",
        package="spring-core", installed_version="6.1.6",
    )
    items = POAMGenerator().generate(findings=[f], manifest=_manifest())
    assert items[0].source_detail.sbom_ref == ""


# ---------------- fingerprint + reconciliation ----------------


def test_fingerprint_stable_across_line_changes():
    f1 = Finding(source="semgrep", rule_id="X", severity="high", file="a.py",
                 line=42, message="", control_ids=[], product="p")
    f2 = Finding(source="semgrep", rule_id="X", severity="high", file="a.py",
                 line=99, message="", control_ids=[], product="p")  # line shifted
    assert fingerprint_for_finding(f1) == fingerprint_for_finding(f2)


def test_fingerprint_distinguishes_different_files():
    f1 = Finding(source="semgrep", rule_id="X", severity="high", file="a.py",
                 line=1, message="", control_ids=[], product="p")
    f2 = Finding(source="semgrep", rule_id="X", severity="high", file="b.py",
                 line=1, message="", control_ids=[], product="p")
    assert fingerprint_for_finding(f1) != fingerprint_for_finding(f2)


def test_reconcile_closes_resolved_items(tmp_path: Path):
    store = AssessmentStore(tmp_path)

    # Previous run: 2 findings.
    prev = AssessmentRecord(
        id="RA-2026-01", product="p", created_at="2026-01-01T00:00:00+00:00",
        payload={"poam": {"items": [
            {"id": "POAM-1", "fingerprint": "FIX-ME", "lifecycle": {"closed_at": None}},
            {"id": "POAM-2", "fingerprint": "STILL-OPEN", "lifecycle": {"closed_at": None}},
        ]}},
    )
    store.save(prev)

    # Current run: only the second finding still present.
    curr = AssessmentRecord(
        id="RA-2026-02", product="p", created_at="2026-02-01T00:00:00+00:00",
        payload={"poam": {"items": [
            {"id": "POAM-99", "fingerprint": "STILL-OPEN"},
        ]}},
    )
    store.save(curr)

    stats = reconcile_against_previous(store, "p", "RA-2026-02")
    assert stats["closed"] == 1
    assert stats["still_open"] == 1
    assert stats["previous_id"] == "RA-2026-01"

    # Verify on disk.
    reread = store.get("p", "RA-2026-01")
    items = reread.payload["poam"]["items"]
    closed = next(i for i in items if i["id"] == "POAM-1")
    still = next(i for i in items if i["id"] == "POAM-2")
    assert closed["lifecycle"]["closed_at"]  # non-empty
    assert still["lifecycle"]["closed_at"] is None


def test_reconcile_skips_already_closed_items(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    prev = AssessmentRecord(
        id="RA-A", product="p", created_at="2026-01-01T00:00:00+00:00",
        payload={"poam": {"items": [
            {"id": "POAM-1", "fingerprint": "FP-A",
             "lifecycle": {"closed_at": "2026-01-15T00:00:00+00:00"}},
        ]}},
    )
    curr = AssessmentRecord(
        id="RA-B", product="p", created_at="2026-02-01T00:00:00+00:00",
        payload={"poam": {"items": []}},
    )
    store.save(prev)
    store.save(curr)

    stats = reconcile_against_previous(store, "p", "RA-B")
    assert stats["closed"] == 0   # already-closed item not re-stamped
    after = store.get("p", "RA-A").payload["poam"]["items"][0]
    assert after["lifecycle"]["closed_at"] == "2026-01-15T00:00:00+00:00"


def test_reconcile_skips_risk_accepted_items(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    prev = AssessmentRecord(
        id="RA-A", product="p", created_at="2026-01-01T00:00:00+00:00",
        payload={"poam": {"items": [
            {"id": "POAM-1", "fingerprint": "FP-A",
             "lifecycle": {"closed_at": None},
             "risk_acceptance": {"accepted_by": "ao@acme"}},
        ]}},
    )
    curr = AssessmentRecord(
        id="RA-B", product="p", created_at="2026-02-01T00:00:00+00:00",
        payload={"poam": {"items": []}},
    )
    store.save(prev)
    store.save(curr)

    stats = reconcile_against_previous(store, "p", "RA-B")
    # AO accepted the residual risk → leave the item alone (not auto-closed).
    assert stats["closed"] == 0
    item = store.get("p", "RA-A").payload["poam"]["items"][0]
    assert item["lifecycle"]["closed_at"] is None


def test_reconcile_no_prior_assessment(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    curr = AssessmentRecord(
        id="RA-ONLY", product="p", created_at="2026-01-01T00:00:00+00:00",
        payload={"poam": {"items": []}},
    )
    store.save(curr)
    stats = reconcile_against_previous(store, "p", "RA-ONLY")
    assert stats == {"closed": 0, "still_open": 0, "previous_id": ""}


# ---------------- end-to-end: two HTTP runs close out a fix ----------------


def test_e2e_two_runs_close_fixed_finding(tmp_path: Path):
    from fastapi.testclient import TestClient
    from orchestrator.server.app import create_app
    from orchestrator.server.state import ServerState

    repo_root = Path(__file__).resolve().parents[2]
    state = ServerState(
        controls_dir=repo_root / "controls" / "baselines",
        tier_mappings_path=repo_root / "controls" / "tier-mappings.yaml",
        products_dir=repo_root / "examples",
        rego_dir=repo_root / "rego" / "gates",
        assessments_dir=tmp_path,
    )
    state.load()
    client = TestClient(create_app(state, api_key=None))

    # Run 1: one critical Semgrep finding.
    r1 = client.post("/v1/products/payment-api/assess", json={
        "results": [{
            "scanner": "semgrep",
            "content": {"results": [{
                "check_id": "py.sqli", "path": "api.py", "start": {"line": 1},
                "extra": {"severity": "ERROR", "message": "SQLi"},
            }], "errors": []},
        }],
    })
    aid1 = r1.json()["assessment_id"]

    # Run 2: same scanner, clean (the developer fixed it).
    r2 = client.post("/v1/products/payment-api/assess", json={
        "results": [{
            "scanner": "semgrep",
            "content": {"results": [], "errors": []},
        }],
    })
    assert r2.status_code == 200
    aid2 = r2.json()["assessment_id"]
    assert aid1 != aid2

    # The prior assessment's POA&M item should now carry closed_at.
    prev = client.get(f"/v1/products/payment-api/assessments/{aid1}").json()
    items = prev["payload"]["poam"]["items"]
    assert items, "expected the prior run to have a POA&M item"
    assert items[0]["lifecycle"]["closed_at"], "fixed finding must be marked closed"
