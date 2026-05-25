"""Tests for orchestrator.vex — CycloneDX VEX parsing, matching, and applying."""

from __future__ import annotations

import pytest

from orchestrator.types import Finding
from orchestrator.vex import (
    VexAnalysis,
    VexDocument,
    VexEntry,
    actionable_findings,
    apply_vex,
    parse_vex_request,
)


def _finding(rule_id: str, package: str = "", severity: str = "high") -> Finding:
    return Finding(
        source="grype",
        rule_id=rule_id,
        severity=severity,
        file="requirements.txt",
        line=0,
        message=f"{rule_id} on {package}",
        control_ids=["PCI-DSS-6.3.1"],
        product="payment-api",
        package=package,
    )


# ---------------------------------------------------------------------------
# parse_vex_request
# ---------------------------------------------------------------------------


class TestParseVexRequest:
    def test_none_returns_none(self) -> None:
        assert parse_vex_request(None) is None

    def test_empty_dict_returns_none(self) -> None:
        assert parse_vex_request({}) is None

    def test_unsupported_format_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported VEX format"):
            parse_vex_request({"format": "csaf", "document": {}})

    def test_missing_document_treated_as_empty(self) -> None:
        doc = parse_vex_request({"format": "cyclonedx"})
        assert isinstance(doc, VexDocument)
        assert doc.entries == []

    def test_non_dict_document_rejected(self) -> None:
        with pytest.raises(ValueError, match="vex.document must be a JSON object"):
            parse_vex_request({"format": "cyclonedx", "document": "not a dict"})

    def test_parses_cyclonedx_vulnerabilities(self) -> None:
        doc = parse_vex_request({
            "format": "cyclonedx",
            "document": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-1",
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_reachable",
                            "detail": "package only loaded in tests",
                        },
                        "affects": [{"ref": "h2"}],
                    },
                    {
                        "id": "CVE-2026-2",
                        "analysis": {"state": "affected", "detail": "fix in 1.6.58"},
                        "affects": [{"ref": "musl"}],
                    },
                ],
            },
        })
        assert doc is not None
        assert len(doc.entries) == 2
        first = doc.entries[0]
        assert first.vulnerability_id == "CVE-2026-1"
        assert first.analysis.state == "not_affected"
        assert first.analysis.justification == "code_not_reachable"
        assert first.package_refs == ("h2",)

    def test_invalid_state_falls_back_to_in_triage(self) -> None:
        doc = parse_vex_request({
            "format": "cyclonedx",
            "document": {"vulnerabilities": [{"id": "CVE-X", "analysis": {"state": "bogus"}}]},
        })
        assert doc is not None
        assert doc.entries[0].analysis.state == "in_triage"

    def test_missing_id_skipped(self) -> None:
        doc = parse_vex_request({
            "format": "cyclonedx",
            "document": {"vulnerabilities": [{"analysis": {"state": "not_affected"}}]},
        })
        assert doc is not None
        assert doc.entries == []


# ---------------------------------------------------------------------------
# VexDocument.lookup — match precedence
# ---------------------------------------------------------------------------


class TestLookup:
    def _doc(self, *entries: VexEntry) -> VexDocument:
        return VexDocument(format="cyclonedx", entries=list(entries))

    def test_exact_package_match(self) -> None:
        doc = self._doc(
            VexEntry("CVE-1", ("h2",), VexAnalysis("not_affected"))
        )
        assert doc.lookup("CVE-1", "h2") is not None

    def test_purl_ref_matches_bare_package_name(self) -> None:
        doc = self._doc(
            VexEntry("CVE-1", ("pkg:maven/com.h2database/h2@1.4.197",), VexAnalysis("not_affected"))
        )
        assert doc.lookup("CVE-1", "h2") is not None

    def test_no_match_when_vuln_id_differs(self) -> None:
        doc = self._doc(VexEntry("CVE-1", ("h2",), VexAnalysis("not_affected")))
        assert doc.lookup("CVE-2", "h2") is None

    def test_wildcard_fallback_when_no_affects_block(self) -> None:
        # An entry with no affects[] matches any package for that CVE.
        doc = self._doc(VexEntry("CVE-1", (), VexAnalysis("affected")))
        hit = doc.lookup("CVE-1", "anything")
        assert hit is not None
        assert hit.analysis.state == "affected"

    def test_wildcard_star_ref(self) -> None:
        doc = self._doc(VexEntry("CVE-1", ("*",), VexAnalysis("in_triage")))
        assert doc.lookup("CVE-1", "h2") is not None

    def test_exact_match_wins_over_wildcard(self) -> None:
        # A specific entry should beat a less-specific one for the same CVE.
        doc = self._doc(
            VexEntry("CVE-1", ("*",), VexAnalysis("in_triage")),
            VexEntry("CVE-1", ("h2",), VexAnalysis("not_affected")),
        )
        hit = doc.lookup("CVE-1", "h2")
        assert hit is not None
        assert hit.analysis.state == "not_affected"

    def test_empty_vulnerability_id_returns_none(self) -> None:
        doc = self._doc(VexEntry("CVE-1", ("h2",), VexAnalysis("not_affected")))
        assert doc.lookup("", "h2") is None


# ---------------------------------------------------------------------------
# apply_vex — tagging + summary
# ---------------------------------------------------------------------------


class TestApplyVex:
    def test_no_document_tags_everything_no_vex(self) -> None:
        findings = [_finding("CVE-1", "h2"), _finding("CVE-2", "musl")]
        summary = apply_vex(findings, None)
        assert summary.vex_provided is False
        assert summary.total_findings == 2
        assert summary.no_vex == 2
        assert summary.actionable == 2
        assert all(f.vex_status == "no_vex" for f in findings)

    def test_not_affected_tags_finding_and_records_suppression(self) -> None:
        findings = [_finding("CVE-1", "h2"), _finding("CVE-2", "musl")]
        doc = parse_vex_request({
            "format": "cyclonedx",
            "document": {
                "vulnerabilities": [{
                    "id": "CVE-1",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                        "detail": "H2 only on test classpath",
                    },
                    "affects": [{"ref": "h2"}],
                }],
            },
        })
        summary = apply_vex(findings, doc)
        assert summary.vex_provided is True
        assert summary.total_findings == 2
        assert summary.not_affected == 1
        assert summary.no_vex == 1
        assert summary.actionable == 1
        assert findings[0].vex_status == "not_affected"
        assert findings[0].vex_justification == "vulnerable_code_not_in_execute_path"
        assert findings[1].vex_status == "no_vex"
        assert summary.suppressed_cves == [{
            "id": "CVE-1",
            "package": "h2",
            "justification": "vulnerable_code_not_in_execute_path",
            "detail": "H2 only on test classpath",
        }]

    def test_state_counters_split_correctly(self) -> None:
        findings = [
            _finding("CVE-1", "a"),
            _finding("CVE-2", "b"),
            _finding("CVE-3", "c"),
            _finding("CVE-4", "d"),
        ]
        doc = parse_vex_request({
            "format": "cyclonedx",
            "document": {
                "vulnerabilities": [
                    {"id": "CVE-1", "analysis": {"state": "not_affected"}, "affects": [{"ref": "a"}]},
                    {"id": "CVE-2", "analysis": {"state": "affected"}, "affects": [{"ref": "b"}]},
                    {"id": "CVE-3", "analysis": {"state": "fixed"}, "affects": [{"ref": "c"}]},
                ],
            },
        })
        summary = apply_vex(findings, doc)
        assert summary.not_affected == 1
        assert summary.affected == 1
        assert summary.fixed == 1
        assert summary.no_vex == 1  # CVE-4 has no entry
        assert summary.actionable == 3  # everything except not_affected

    def test_summary_to_dict_collapses_when_not_provided(self) -> None:
        summary = apply_vex([_finding("CVE-1", "a")], None)
        assert summary.to_dict() == {"vex_provided": False}

    def test_summary_to_dict_with_vex_provided(self) -> None:
        doc = parse_vex_request({
            "format": "cyclonedx",
            "document": {"vulnerabilities": [{
                "id": "CVE-1",
                "analysis": {"state": "not_affected", "justification": "code_not_present"},
                "affects": [{"ref": "a"}],
            }]},
        })
        summary = apply_vex([_finding("CVE-1", "a")], doc)
        d = summary.to_dict()
        assert d["vex_provided"] is True
        assert d["not_affected"] == 1
        assert d["actionable"] == 0
        assert d["suppressed_cves"][0]["id"] == "CVE-1"


class TestActionableFindings:
    def test_drops_not_affected_only(self) -> None:
        a = _finding("CVE-1", "a")
        a.vex_status = "not_affected"
        b = _finding("CVE-2", "b")
        b.vex_status = "affected"
        c = _finding("CVE-3", "c")
        c.vex_status = "in_triage"
        d = _finding("CVE-4", "d")
        d.vex_status = "no_vex"
        out = actionable_findings([a, b, c, d])
        assert [f.rule_id for f in out] == ["CVE-2", "CVE-3", "CVE-4"]
