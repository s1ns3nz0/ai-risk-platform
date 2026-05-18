"""HTTP-layer tests for submitted-scanners tracking + framework aliases.

Covers:
- A scanner payload with zero findings still credits the scanner in the SAR
  (gitleaks/spotbugs 'clean scan' must produce 'satisfied' on their
  assessed controls instead of 'not-assessed').
- Checkov framework variants (checkov-k8s, checkov-dockerfile) route to
  the checkov parser.
- SpotBugs raw-XML body (string content) is parsed and credits spotbugs.
"""

from __future__ import annotations


def _payload(*entries):
    return {"results": list(entries), "async_mode": False}


def _gitleaks_clean_sarif():
    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}],
    }


def _checkov_k8s_sample():
    return {
        "check_type": "kubernetes",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_15",
                    "check_name": "Image pull policy not set to Always",
                    "file_path": "deploy/k8s/30-deployment.yaml",
                    "file_line_range": [20, 30],
                    "resource": "Deployment.payment-api.payment-api",
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
        "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
    }


def _spotbugs_empty_xml() -> str:
    # Real spotbugs output for a clean run. Parser must accept this and
    # the HTTP layer must still record spotbugs as submitted.
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<BugCollection version='4.8.3' sequence='0' timestamp='0' analysisTimestamp='0' release=''>"
        "<Project projectName=''></Project>"
        "<FindBugsSummary total_bugs='0' total_classes='0' total_size='0' num_packages='0' />"
        "</BugCollection>"
    )


def _spotbugs_one_bug_xml() -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<BugCollection version='4.8.3'>"
        "<BugInstance type='EI_EXPOSE_REP' priority='2' category='MALICIOUS_CODE'>"
        "<SourceLine classname='com.x.Foo' start='42' end='42' "
        "sourcefile='Foo.java' sourcepath='com/x/Foo.java' />"
        "<LongMessage>Foo.method() may expose internal rep</LongMessage>"
        "</BugInstance>"
        "</BugCollection>"
    )


# ---- RP-1: zero-finding scanner still counts as submitted ----


def test_gitleaks_clean_sarif_credits_scanner_in_sar(client):
    """gitleaks SARIF with results=[] must yield 'satisfied' on at least
    one gitleaks-assessed control — not 'not-assessed' across the board.
    """
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({"scanner": "gitleaks", "content": _gitleaks_clean_sarif()}),
    )
    assert r.status_code == 200, r.text
    sar = r.json()["sar"]

    gitleaks_satisfied = [
        a for a in sar["control_assessments"]
        if a["status"] == "satisfied" and "gitleaks" in a["assessor"]
    ]
    assert gitleaks_satisfied, (
        "expected at least one control to be 'satisfied' by gitleaks after "
        "a clean scan; got none"
    )
    # And none of the gitleaks-assessed controls should be falsely flagged
    # as 'Scanner(s) did not run' since the payload was submitted.
    gitleaks_not_assessed = [
        a for a in sar["control_assessments"]
        if "gitleaks" in a["assessor"]
        and a["status"] == "not-assessed"
        and "did not run" in a["findings_summary"]
    ]
    assert not gitleaks_not_assessed, (
        f"gitleaks payload was submitted but {len(gitleaks_not_assessed)} "
        "controls still claim 'Scanner(s) did not run'"
    )


def test_gitleaks_native_empty_array_credits_scanner(client):
    """Gitleaks native JSON (bare array) with zero entries — same outcome."""
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({"scanner": "gitleaks", "content": []}),
    )
    assert r.status_code == 200, r.text
    sar = r.json()["sar"]
    assert any(
        a["status"] == "satisfied" and "gitleaks" in a["assessor"]
        for a in sar["control_assessments"]
    )


# ---- RP-2: Checkov framework variants route to checkov parser ----


def test_checkov_k8s_alias_routes_and_creates_findings(client):
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({"scanner": "checkov-k8s", "content": _checkov_k8s_sample()}),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_count"] == 1


def test_checkov_dockerfile_alias_routes(client):
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({
            "scanner": "checkov-dockerfile",
            "content": {
                "check_type": "dockerfile",
                "results": {"failed_checks": [], "passed_checks": []},
                "summary": {"passed": 0, "failed": 0},
            },
        }),
    )
    assert r.status_code == 200, r.text
    # Zero findings but scanner must be credited.
    sar = r.json()["sar"]
    assert any(
        a["status"] == "satisfied" and "checkov" in a["assessor"]
        for a in sar["control_assessments"]
    )


# ---- RP-3: SpotBugs raw XML path ----


def test_spotbugs_xml_string_with_bug(client):
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({"scanner": "spotbugs", "content": _spotbugs_one_bug_xml()}),
    )
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


def test_spotbugs_empty_xml_accepted(client):
    """0-bug BugCollection — parser must accept it without erroring; the
    bundled controls don't use spotbugs as an assessor, so we only assert
    that the request succeeds with zero findings.
    """
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({"scanner": "spotbugs", "content": _spotbugs_empty_xml()}),
    )
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 0


def test_spotbugs_xml_alias_accepted(client):
    """`spotbugs-xml` is accepted by the validator and routes to spotbugs."""
    r = client.post(
        "/v1/products/payment-api/assess",
        json=_payload({"scanner": "spotbugs-xml", "content": _spotbugs_one_bug_xml()}),
    )
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1
