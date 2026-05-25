"""VEX (Vulnerability Exploitability eXchange) — CycloneDX 1.4+ support.

Parses a VEX document, matches its analysis statements against Grype-style
SCA findings, and produces a `VexSummary` plus VEX-annotated findings.

`not_affected` findings are tagged so the gate / SP 800-30 / SAR / POA&M
pipelines can suppress them from actionable counts while keeping them in
the audit trail.

CycloneDX VEX reference:
  - state: not_affected | affected | in_triage | fixed | under_investigation
  - justification (not_affected only):
      code_not_present, code_not_reachable, vulnerable_code_not_in_execute_path,
      requires_configuration, requires_dependency, requires_environment,
      protected_by_mitigating_control
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from orchestrator.types import Finding


_VALID_STATES: frozenset[str] = frozenset({
    "not_affected",
    "affected",
    "in_triage",
    "fixed",
    "under_investigation",
})


@dataclass(frozen=True)
class VexAnalysis:
    state: str
    justification: str = ""
    detail: str = ""


@dataclass(frozen=True)
class VexEntry:
    vulnerability_id: str
    package_refs: tuple[str, ...]
    analysis: VexAnalysis


@dataclass
class VexDocument:
    format: str
    entries: list[VexEntry] = field(default_factory=list)

    def lookup(self, vulnerability_id: str, package: str) -> VexEntry | None:
        """Find a VEX entry by (vulnerability_id, package).

        Match precedence:
          1. exact (vuln_id + package matches one of `affects[].ref`, with
             PURL `pkg:.../<package>@...` recognised)
          2. wildcard (vuln_id with no `affects` block, or `affects[].ref == "*"`)
        """
        if not vulnerability_id:
            return None

        wildcard_hit: VexEntry | None = None
        for e in self.entries:
            if e.vulnerability_id != vulnerability_id:
                continue
            if package and any(_ref_matches(ref, package) for ref in e.package_refs):
                return e
            if not e.package_refs or "*" in e.package_refs:
                wildcard_hit = wildcard_hit or e
        return wildcard_hit


@dataclass
class VexSummary:
    vex_provided: bool = False
    total_findings: int = 0
    not_affected: int = 0
    affected: int = 0
    in_triage: int = 0
    fixed: int = 0
    under_investigation: int = 0
    no_vex: int = 0
    actionable: int = 0
    suppressed_cves: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        if not self.vex_provided:
            return {"vex_provided": False}
        return {
            "vex_provided": True,
            "total_findings": self.total_findings,
            "not_affected": self.not_affected,
            "affected": self.affected,
            "in_triage": self.in_triage,
            "fixed": self.fixed,
            "under_investigation": self.under_investigation,
            "no_vex": self.no_vex,
            "actionable": self.actionable,
            "suppressed_cves": list(self.suppressed_cves),
        }


def _ref_matches(ref: str, package: str) -> bool:
    """True if a CycloneDX `affects[].ref` value points to `package`.

    Handles bare package names ("h2") and PURL refs
    ("pkg:maven/com.h2database/h2@1.4.197").
    """
    if not ref:
        return False
    if ref == package:
        return True
    # PURL forms: pkg:type/group/name@version or pkg:type/name@version
    if f"/{package}@" in ref or f"/{package}/" in ref:
        return True
    return False


def parse_vex_request(vex: dict[str, Any] | None) -> VexDocument | None:
    """Parse the request body's `vex` field into a `VexDocument`.

    Returns None when no VEX was supplied so the caller can keep the
    pre-existing "no VEX" behaviour.
    """
    if not vex:
        return None
    fmt = (vex.get("format") or "cyclonedx").lower()
    if fmt != "cyclonedx":
        raise ValueError(f"unsupported VEX format: {fmt!r} (only 'cyclonedx' is supported)")
    document = vex.get("document") or {}
    if not isinstance(document, dict):
        raise ValueError("vex.document must be a JSON object")
    return _parse_cyclonedx(document)


def _parse_cyclonedx(document: dict[str, Any]) -> VexDocument:
    entries: list[VexEntry] = []
    raw_vulns = document.get("vulnerabilities") or []
    if not isinstance(raw_vulns, list):
        return VexDocument(format="cyclonedx", entries=entries)

    for v in raw_vulns:
        if not isinstance(v, dict):
            continue
        vid = str(v.get("id") or "").strip()
        if not vid:
            continue
        analysis_raw = v.get("analysis") or {}
        state = str(analysis_raw.get("state") or "in_triage").strip()
        if state not in _VALID_STATES:
            state = "in_triage"
        affects = v.get("affects") or []
        refs: list[str] = []
        if isinstance(affects, list):
            for a in affects:
                if isinstance(a, dict):
                    ref = a.get("ref")
                    if isinstance(ref, str) and ref:
                        refs.append(ref)
        entries.append(
            VexEntry(
                vulnerability_id=vid,
                package_refs=tuple(refs),
                analysis=VexAnalysis(
                    state=state,
                    justification=str(analysis_raw.get("justification") or ""),
                    detail=str(analysis_raw.get("detail") or ""),
                ),
            )
        )
    return VexDocument(format="cyclonedx", entries=entries)


def apply_vex(
    findings: list[Finding],
    document: VexDocument | None,
) -> VexSummary:
    """Tag each finding with VEX status in place; return a summary.

    When `document` is None, every finding is tagged `no_vex` and the
    returned summary reports `vex_provided=False`.

    A finding's `rule_id` is treated as the vulnerability identifier
    (CVE/GHSA). Non-SCA findings (no CVE/GHSA in rule_id) won't match
    any VEX entry and stay `no_vex`.
    """
    total = len(findings)
    if document is None:
        for f in findings:
            f.vex_status = "no_vex"
            f.vex_justification = ""
            f.vex_detail = ""
        return VexSummary(
            vex_provided=False,
            total_findings=total,
            no_vex=total,
            actionable=total,
        )

    summary = VexSummary(vex_provided=True, total_findings=total)
    suppressed: list[dict[str, str]] = []

    for f in findings:
        entry = document.lookup(f.rule_id, f.package)
        if entry is None:
            f.vex_status = "no_vex"
            f.vex_justification = ""
            f.vex_detail = ""
            summary.no_vex += 1
            continue
        state = entry.analysis.state
        f.vex_status = state
        f.vex_justification = entry.analysis.justification
        f.vex_detail = entry.analysis.detail
        if state == "not_affected":
            summary.not_affected += 1
            suppressed.append({
                "id": f.rule_id,
                "package": f.package,
                "justification": entry.analysis.justification,
                "detail": entry.analysis.detail,
            })
        elif state == "affected":
            summary.affected += 1
        elif state == "in_triage":
            summary.in_triage += 1
        elif state == "fixed":
            summary.fixed += 1
        elif state == "under_investigation":
            summary.under_investigation += 1

    summary.suppressed_cves = suppressed
    summary.actionable = total - summary.not_affected
    return summary


def actionable_findings(findings: list[Finding]) -> list[Finding]:
    """Filter out VEX-suppressed (not_affected) findings."""
    return [f for f in findings if f.vex_status != "not_affected"]
