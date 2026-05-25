"""End-to-end tests for VEX support on /v1/products/{name}/assess.

Covers the three scenarios from the VEX spec:
  1. No VEX field           → response.vex_summary.vex_provided == False
  2. VEX present, 0 matches → vex_summary present, not_affected == 0
  3. VEX suppresses N       → findings_count drops by N, suppressed_cves listed
"""

from __future__ import annotations

import json
from typing import Any


def _grype_payload(matches: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "scanner": "grype",
        "content": {
            "matches": matches,
            "descriptor": {"name": "grype"},
        },
    }


def _match(cve: str, package: str, severity: str = "Critical") -> dict[str, Any]:
    return {
        "vulnerability": {
            "id": cve,
            "severity": severity,
            "cwes": ["CWE-79"],
        },
        "artifact": {"name": package, "version": "1.0.0", "locations": []},
    }


def _request(matches: list[dict[str, Any]], vex: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "trigger": "pre_merge",
        "async_mode": False,
        "results": [_grype_payload(matches)],
    }
    if vex is not None:
        body["vex"] = vex
    return body


def test_no_vex_field_keeps_existing_behaviour(client) -> None:
    """When no `vex` is in the request, response surfaces vex_provided=False
    and findings_count equals the total parsed findings."""
    body = _request([_match("CVE-2026-A", "h2"), _match("CVE-2026-B", "musl")])
    r = client.post("/v1/products/payment-api/assess", json=body)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["vex_summary"] == {"vex_provided": False}
    assert payload["findings_count"] == 2


def test_vex_with_zero_matches_provided_but_no_suppression(client) -> None:
    """VEX document present but no entries — vex_provided=true, not_affected=0."""
    body = _request(
        [_match("CVE-2026-A", "h2"), _match("CVE-2026-B", "musl")],
        vex={"format": "cyclonedx", "document": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "vulnerabilities": [],
        }},
    )
    r = client.post("/v1/products/payment-api/assess", json=body)
    assert r.status_code == 200, r.text
    summary = r.json()["vex_summary"]
    assert summary["vex_provided"] is True
    assert summary["total_findings"] == 2
    assert summary["not_affected"] == 0
    assert summary["no_vex"] == 2
    assert summary["actionable"] == 2
    assert summary["suppressed_cves"] == []


def test_vex_not_affected_suppresses_finding_from_actionable_set(client) -> None:
    """A `not_affected` CVE drops out of findings_count and POA&M items
    but stays visible via vex_summary.suppressed_cves."""
    body = _request(
        [
            _match("CVE-2026-A", "h2"),     # to be suppressed
            _match("CVE-2026-B", "musl"),
            _match("CVE-2026-C", "openssl"),
        ],
        vex={"format": "cyclonedx", "document": {
            "vulnerabilities": [
                {
                    "id": "CVE-2026-A",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                        "detail": "H2 only used in test scope",
                    },
                    "affects": [{"ref": "h2"}],
                },
                {
                    "id": "CVE-2026-B",
                    "analysis": {"state": "affected", "detail": "Fix in musl 1.6.58"},
                    "affects": [{"ref": "musl"}],
                },
            ],
        }},
    )
    r = client.post("/v1/products/payment-api/assess", json=body)
    assert r.status_code == 200, r.text
    payload = r.json()

    summary = payload["vex_summary"]
    assert summary["vex_provided"] is True
    assert summary["total_findings"] == 3
    assert summary["not_affected"] == 1
    assert summary["affected"] == 1
    assert summary["no_vex"] == 1
    assert summary["actionable"] == 2

    # findings_count is the actionable count (suppressed CVE excluded).
    assert payload["findings_count"] == 2

    # The suppressed CVE shows up with its justification + detail.
    suppressed = summary["suppressed_cves"]
    assert len(suppressed) == 1
    assert suppressed[0]["id"] == "CVE-2026-A"
    assert suppressed[0]["justification"] == "vulnerable_code_not_in_execute_path"

    # The suppressed CVE must NOT appear as a POA&M item; the others should.
    poam_ids = {
        item.get("control_id", "") for item in payload["poam"]["items"]
    }
    poam_cves: set[str] = set()
    for item in payload["poam"]["items"]:
        msg = json.dumps(item)
        for cve in ("CVE-2026-A", "CVE-2026-B", "CVE-2026-C"):
            if cve in msg:
                poam_cves.add(cve)
    assert "CVE-2026-A" not in poam_cves
    assert {"CVE-2026-B", "CVE-2026-C"} <= poam_cves


def test_unsupported_vex_format_returns_400(client) -> None:
    """Malformed VEX (unsupported format) is a client error, not a 500."""
    body = _request(
        [_match("CVE-2026-A", "h2")],
        vex={"format": "csaf", "document": {}},
    )
    r = client.post("/v1/products/payment-api/assess", json=body)
    assert r.status_code == 400
    assert "invalid vex" in r.json()["detail"]


def test_vex_purl_ref_matches_package_name(client) -> None:
    """CycloneDX `affects[].ref` in PURL form should match the bare package name."""
    body = _request(
        [_match("CVE-2026-A", "h2")],
        vex={"format": "cyclonedx", "document": {
            "vulnerabilities": [{
                "id": "CVE-2026-A",
                "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
                "affects": [{"ref": "pkg:maven/com.h2database/h2@1.4.197"}],
            }],
        }},
    )
    r = client.post("/v1/products/payment-api/assess", json=body)
    assert r.status_code == 200, r.text
    summary = r.json()["vex_summary"]
    assert summary["not_affected"] == 1
    assert summary["actionable"] == 0
