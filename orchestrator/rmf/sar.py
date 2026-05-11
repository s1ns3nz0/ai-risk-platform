"""Security Assessment Report (SAR) — RMF Step 5 deliverable.

Generates a deterministic SAR from scanner findings + controls repository.
AI is NOT used — SAR is purely findings-based.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from orchestrator.controls.models import Control
from orchestrator.controls.repository import ControlsRepository
from orchestrator.rmf.models import SP80030Report
from orchestrator.types import Finding, GateDecision


@dataclass
class ControlAssessment:
    """Per-control assessment status (RMF Step 5)."""

    control_id: str
    title: str
    framework: str
    status: str  # "satisfied" / "other-than-satisfied" / "not-assessed"
    evidence_type: str  # "automated" / "manual" / "none"
    assessor: str  # "semgrep" / "checkov" / "manual review required"
    findings_count: int
    findings_summary: str  # brief description of what was found
    risk_level: str  # from SP 800-30 assessment


@dataclass
class SecurityAssessmentReport:
    """SAR — RMF Step 5 deliverable."""

    report_id: str  # SAR-YYYY-MMDD-NNN
    product: str
    generated_at: str
    system_description: str  # from manifest
    assessment_methodology: str  # "Automated scanning + SP 800-30 risk assessment"

    # Per-control results
    control_assessments: list[ControlAssessment]

    # Summary statistics
    total_controls: int
    satisfied: int
    other_than_satisfied: int
    not_assessed: int
    coverage_percentage: float

    # Linked risk assessment
    risk_assessment_id: str  # SP80030Report reference

    # Overall determination
    overall_risk: str  # "acceptable" / "unacceptable"
    authorization_recommendation: str  # "ATO" / "DATO" / "ATO-with-conditions"


class SARGenerator:
    """Generate Security Assessment Report from findings + controls.

    Maps:
    - Controls with scanner findings -> "satisfied" (automated evidence)
    - Controls with findings flagging issues -> "other-than-satisfied"
    - Controls with no scanner mapping -> "not-assessed" (manual review needed)
    """

    def __init__(self, controls_repo: ControlsRepository) -> None:
        self._controls = controls_repo

    def generate(
        self,
        product: str,
        findings: list[Finding],
        gate_decision: GateDecision,
        risk_report: SP80030Report | None = None,
    ) -> SecurityAssessmentReport:
        """Generate SAR."""
        now = datetime.now(timezone.utc)
        report_id = f"SAR-{now.strftime('%Y')}-{now.strftime('%m%d')}-001"

        # Collect all scanners that produced findings
        scanners_that_ran: set[str] = {f.source for f in findings}

        # Build per-control index of findings
        control_findings: dict[str, list[Finding]] = {}
        for f in findings:
            for cid in f.control_ids:
                control_findings.setdefault(cid, []).append(f)

        # Assess each control
        assessments: list[ControlAssessment] = []
        for control_id, control in self._controls.controls.items():
            ctrl_findings = control_findings.get(control_id, [])
            assessment = self._assess_control(
                control, ctrl_findings, scanners_that_ran,
            )
            assessments.append(assessment)

        satisfied = sum(1 for a in assessments if a.status == "satisfied")
        other_than_satisfied = sum(1 for a in assessments if a.status == "other-than-satisfied")
        not_assessed = sum(1 for a in assessments if a.status == "not-assessed")
        total = len(assessments)
        coverage = round(satisfied / total * 100, 1) if total > 0 else 0.0

        # Authorization recommendation from gate decision
        if gate_decision.passed:
            overall_risk = "acceptable"
            authorization = "ATO"
        else:
            overall_risk = "unacceptable"
            authorization = "DATO"

        return SecurityAssessmentReport(
            report_id=report_id,
            product=product,
            generated_at=now.isoformat(),
            system_description=f"Security assessment for {product}",
            assessment_methodology="Automated scanning + SP 800-30 risk assessment",
            control_assessments=assessments,
            total_controls=total,
            satisfied=satisfied,
            other_than_satisfied=other_than_satisfied,
            not_assessed=not_assessed,
            coverage_percentage=coverage,
            risk_assessment_id=risk_report.report_id if risk_report else "",
            overall_risk=overall_risk,
            authorization_recommendation=authorization,
        )

    def _assess_control(
        self,
        control: "Control",
        findings: list[Finding],
        scanners_that_ran: set[str],
    ) -> ControlAssessment:
        """Assess a single control.

        Logic:
        - Has verification_methods AND scanner ran AND 0 issues -> "satisfied"
        - Has verification_methods AND scanner ran AND issues found -> "other-than-satisfied"
        - Has verification_methods but scanner NOT in findings -> "not-assessed"
        - No verification_methods -> "not-assessed" (manual only)
        """
        if not control.verification_methods:
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                framework=control.framework,
                status="not-assessed",
                evidence_type="none",
                assessor="manual review required",
                findings_count=0,
                findings_summary="No automated verification methods defined",
                risk_level="unknown",
            )

        required_scanners = {vm.scanner for vm in control.verification_methods}
        ran_scanners = required_scanners & scanners_that_ran

        if not ran_scanners:
            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                framework=control.framework,
                status="not-assessed",
                evidence_type="none",
                assessor=", ".join(sorted(required_scanners)),
                findings_count=0,
                findings_summary="Scanner(s) did not run",
                risk_level="unknown",
            )

        assessor = ", ".join(sorted(ran_scanners))

        if findings:
            # Issues found for this control
            severity_counts: dict[str, int] = {}
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            summary_parts = [f"{count} {sev}" for sev, count in sorted(severity_counts.items())]
            summary = f"Found {len(findings)} issue(s): {', '.join(summary_parts)}"

            return ControlAssessment(
                control_id=control.id,
                title=control.title,
                framework=control.framework,
                status="other-than-satisfied",
                evidence_type="automated",
                assessor=assessor,
                findings_count=len(findings),
                findings_summary=summary,
                risk_level=self._worst_severity(findings),
            )

        # Scanner ran, no issues for this control
        return ControlAssessment(
            control_id=control.id,
            title=control.title,
            framework=control.framework,
            status="satisfied",
            evidence_type="automated",
            assessor=assessor,
            findings_count=0,
            findings_summary="No issues found",
            risk_level="none",
        )

    @staticmethod
    def _worst_severity(findings: list[Finding]) -> str:
        """Return the worst severity from a list of findings."""
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        worst = max(findings, key=lambda f: order.get(f.severity, -1))
        return worst.severity
