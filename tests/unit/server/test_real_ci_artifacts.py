"""End-to-end test against the actual artifacts a CI pipeline produces.

These fixtures came from `gh run download` on a real GitHub Actions run.
The platform must accept the same JSON envelope shape the CI POSTs:
null content for empty scans, base64-encoded XML for Spotbugs, nested
Checkov shape, etc.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ci-artifacts"


def _load_json(name: str):
    return json.loads((_FIXTURES / name).read_text())


def _load_text(name: str) -> str:
    return (_FIXTURES / name).read_text()


# ---------------- per-scanner ----------------


def test_real_hadolint_sarif(client):
    payload = {
        "results": [{"scanner": "hadolint", "content": _load_json("hadolint.sarif.json")}],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text


def test_real_zap_json(client):
    payload = {
        "results": [{"scanner": "zap", "content": _load_json("zap.json")}],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text


def test_real_checkov_nested_shape(client):
    """Real Checkov is {check_type, results: {passed_checks, failed_checks}, summary, url}
    — top-level passed_checks/failed_checks do NOT exist."""
    payload = {
        "results": [{"scanner": "checkov", "content": _load_json("checkov-dockerfile.json")}],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    # 1 failed_check in the real artifact.
    assert r.json()["findings_count"] >= 1


def test_real_checkov_autodetected(client):
    """Without `scanner` set, detect_scanner_from_content must recognize
    the real Checkov shape via check_type+results+summary."""
    payload = {"results": [{"content": _load_json("checkov-dockerfile.json")}]}
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] >= 1


def test_real_spotbugs_xml_raw_string(client):
    payload = {
        "results": [{"scanner": "spotbugs", "content": _load_text("spotbugs.xml")}],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text


def test_real_spotbugs_xml_base64(client):
    """The actual CI base64-encodes the XML before stuffing it into JSON."""
    raw_xml = _load_text("spotbugs.xml")
    b64 = base64.b64encode(raw_xml.encode("utf-8")).decode("ascii")
    payload = {
        "results": [{"scanner": "spotbugs", "content": b64}],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text


# ---------------- resilience ----------------


def test_null_content_skipped_not_rejected(client):
    """When a scanner produced an empty result, the CI may POST content: null.
    Platform must NOT 422 — it must skip the entry with a warning."""
    payload = {
        "results": [
            {"scanner": "grype-image", "content": None},
            {"scanner": "semgrep", "content": {"results": [
                {"check_id": "x", "path": "a.py", "start": {"line": 1},
                 "extra": {"severity": "ERROR", "message": "m"}},
            ], "errors": []}},
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    # Only the semgrep finding makes it through; null entry was skipped silently.
    assert r.json()["findings_count"] == 1


def test_empty_dict_content_skipped(client):
    payload = {
        "results": [
            {"scanner": "grype", "content": {}},
            {"scanner": "gitleaks", "content": [
                {"RuleID": "aws-key", "File": "f", "StartLine": 1, "Description": "x"},
            ]},
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


def test_full_ci_batch_with_mixed_signals(client):
    """Simulates the real CI bundle: some scanners found nothing, some have
    base64 XML, some have JSON. The batch must succeed end-to-end."""
    raw_xml = _load_text("spotbugs.xml")
    b64 = base64.b64encode(raw_xml.encode("utf-8")).decode("ascii")
    payload = {
        "trigger": "pre_merge",
        "results": [
            {"scanner": "hadolint", "content": _load_json("hadolint.sarif.json")},
            {"scanner": "grype-image", "content": None},   # empty file
            {"scanner": "zap", "content": _load_json("zap.json")},
            {"scanner": "spotbugs", "content": b64},        # base64 XML
            {"scanner": "checkov", "content": _load_json("checkov-dockerfile.json")},
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text


def test_string_content_for_non_spotbugs_rejected_gracefully(client):
    """A string content for semgrep must be skipped (logged), not crash the batch."""
    payload = {
        "results": [
            {"scanner": "semgrep", "content": "<xml>oops</xml>"},
            {"scanner": "gitleaks", "content": [
                {"RuleID": "aws-key", "File": "f", "StartLine": 1, "Description": "x"},
            ]},
        ],
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] == 1


def test_numeric_content_still_rejected(client):
    """Non-container, non-string content (numbers, booleans) is still rejected
    at the validator level — that's a malformed request, not an empty scan."""
    payload = {"results": [{"scanner": "semgrep", "content": 42}]}
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 422


# ---------------- spotbugs unit ----------------


def test_spotbugs_parser_handles_zero_bugs():
    """The real artifact has total_bugs='0' — no BugInstance elements.
    Parser must return [] not raise."""
    from unittest.mock import MagicMock
    from orchestrator.scanners.spotbugs import SpotbugsScanner

    mapper = MagicMock()
    mapper.map_finding.return_value = []
    findings = SpotbugsScanner(mapper).parse_output(_load_text("spotbugs.xml"))
    assert findings == []


def test_spotbugs_parser_handles_bug_instances():
    """Construct a minimal BugCollection with one bug and verify parsing."""
    from unittest.mock import MagicMock
    from orchestrator.scanners.spotbugs import SpotbugsScanner

    xml = """<?xml version='1.0'?>
<BugCollection version='4.8.3'>
  <Project projectName='x'></Project>
  <BugInstance type='EI_EXPOSE_REP' priority='2' category='MALICIOUS_CODE'>
    <Class classname='com.x.Foo'/>
    <SourceLine classname='com.x.Foo' start='42' end='42'
                sourcefile='Foo.java' sourcepath='com/x/Foo.java'/>
    <LongMessage>Foo.getThing() may expose internal representation</LongMessage>
  </BugInstance>
</BugCollection>"""
    mapper = MagicMock()
    mapper.map_finding.return_value = []
    findings = SpotbugsScanner(mapper).parse_output(xml)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "spotbugs"
    assert f.rule_id == "EI_EXPOSE_REP"
    assert f.severity == "medium"  # priority=2
    assert f.file == "com/x/Foo.java"
    assert f.line == 42
    assert "may expose internal representation" in f.message


def test_spotbugs_parser_handles_base64():
    """Same XML, base64-encoded — should parse identically."""
    from unittest.mock import MagicMock
    from orchestrator.scanners.spotbugs import SpotbugsScanner

    xml = "<BugCollection><BugInstance type='X' priority='1'/></BugCollection>"
    b64 = base64.b64encode(xml.encode()).decode()
    mapper = MagicMock()
    mapper.map_finding.return_value = []
    findings = SpotbugsScanner(mapper).parse_output(b64)
    assert len(findings) == 1
    assert findings[0].rule_id == "X"
    assert findings[0].severity == "high"  # priority=1


def test_spotbugs_parser_handles_malformed_input():
    from unittest.mock import MagicMock
    from orchestrator.scanners.spotbugs import SpotbugsScanner

    mapper = MagicMock()
    mapper.map_finding.return_value = []
    assert SpotbugsScanner(mapper).parse_output("not xml or base64") == []
