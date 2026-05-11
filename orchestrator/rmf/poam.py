"""POA&M and Authorization Engine — RMF Step 6 deliverables.

Generates Plan of Action & Milestones from findings and produces
deterministic authorization decisions. AI is NOT used.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from orchestrator.rmf.models import SP80030Report
from orchestrator.types import Finding, GateDecision


# Severity -> deadline in days
_DEADLINE_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}

# Severity -> risk level mapping (when no SP 800-30 report available)
_SEVERITY_TO_RISK: dict[str, str] = {
    "critical": "very-high",
    "high": "high",
    "medium": "moderate",
    "low": "low",
    "info": "very-low",
}

# Severity -> cost estimate heuristic
_SEVERITY_TO_COST: dict[str, str] = {
    "critical": "high",
    "high": "moderate",
    "medium": "moderate",
    "low": "low",
    "info": "low",
}


@dataclass
class POAMItem:
    """Single weakness + remediation plan."""

    id: str  # POAM-YYYY-MMDD-NNN
    weakness: str  # what's wrong
    control_id: str  # which control is affected
    source: str  # "semgrep" / "grype" / "checkov" / etc.
    finding_id: str  # CVE or rule ID
    severity: str  # critical / high / medium / low
    risk_level: str  # from SP 800-30 assessment
    status: str  # "open" / "in-progress" / "completed" / "accepted"

    # Milestones
    milestones: list[dict[str, str]]  # [{description, target_date, status}]
    scheduled_completion: str  # target date
    responsible: str  # "security-engineer" / "dev-team" / etc.
    cost_estimate: str  # "low" / "moderate" / "high"

    # Links
    finding_evidence: str  # reference to JSONL/DefectDojo
    override_id: str  # if overridden, link to OverrideRecord


@dataclass
class AuthorizationDecision:
    """RMF Step 6 authorization decision."""

    decision: str  # "ATO" / "DATO" / "ATO-with-conditions"
    risk_level: str  # overall risk from SP 800-30
    conditions: list[str]  # POA&M items required for ATO-with-conditions
    authorizer: str  # "automated-gate" or role
    timestamp: str
    valid_until: str  # re-authorization date
    reasoning: str


class POAMGenerator:
    """Generate POA&M from findings + risk assessment."""

    _counter: int = 0

    def generate(
        self,
        findings: list[Finding],
        risk_report: SP80030Report | None = None,
        gate_decision: GateDecision | None = None,
    ) -> list[POAMItem]:
        """Generate POA&M items from findings.

        Priority -> deadline mapping:
        - critical: 7 days
        - high: 30 days
        - moderate/medium: 90 days
        - low: 180 days

        Each item has 4 milestones:
        1. Identify fix (day 1)
        2. Implement fix (50% of deadline)
        3. Verify in staging (75% of deadline)
        4. Deploy to production (deadline)
        """
        now = datetime.now(timezone.utc)
        items: list[POAMItem] = []

        # Build risk level lookup from SP 800-30 report
        risk_lookup: dict[str, str] = {}
        if risk_report:
            for rd in risk_report.risk_determinations:
                risk_lookup[rd.threat_event_id] = rd.risk_level

        for finding in findings:
            POAMGenerator._counter += 1
            item_id = f"POAM-{now.strftime('%Y')}-{now.strftime('%m%d')}-{POAMGenerator._counter:03d}"

            deadline_days = _DEADLINE_DAYS.get(finding.severity, 90)
            deadline_date = now + timedelta(days=deadline_days)

            risk_level = _SEVERITY_TO_RISK.get(finding.severity, "moderate")

            # Use first control_id (primary affected control)
            control_id = finding.control_ids[0] if finding.control_ids else ""

            milestones = self._build_milestones(now, deadline_days)

            items.append(
                POAMItem(
                    id=item_id,
                    weakness=finding.message,
                    control_id=control_id,
                    source=finding.source,
                    finding_id=finding.rule_id,
                    severity=finding.severity,
                    risk_level=risk_level,
                    status="open",
                    milestones=milestones,
                    scheduled_completion=deadline_date.strftime("%Y-%m-%d"),
                    responsible=self._assign_responsible(finding.severity),
                    cost_estimate=_SEVERITY_TO_COST.get(finding.severity, "moderate"),
                    finding_evidence="findings.jsonl",
                    override_id="",
                )
            )

        return items

    @staticmethod
    def _build_milestones(start: datetime, deadline_days: int) -> list[dict[str, str]]:
        """Build 4 milestones with target dates."""
        return [
            {
                "description": "Identify fix",
                "target_date": (start + timedelta(days=1)).strftime("%Y-%m-%d"),
                "status": "open",
            },
            {
                "description": "Implement fix",
                "target_date": (start + timedelta(days=deadline_days // 2)).strftime("%Y-%m-%d"),
                "status": "open",
            },
            {
                "description": "Verify in staging",
                "target_date": (start + timedelta(days=int(deadline_days * 0.75))).strftime("%Y-%m-%d"),
                "status": "open",
            },
            {
                "description": "Deploy to production",
                "target_date": (start + timedelta(days=deadline_days)).strftime("%Y-%m-%d"),
                "status": "open",
            },
        ]

    @staticmethod
    def _assign_responsible(severity: str) -> str:
        """Assign responsible party based on severity."""
        if severity in ("critical", "high"):
            return "security-engineer"
        return "dev-team"


class AuthorizationEngine:
    """RMF Step 6 authorization decision.

    Maps:
    - Gate PASS + no open POA&M + no overrides -> ATO
    - Gate BLOCK -> DATO
    - Gate PASS + open POA&M items -> ATO-with-conditions
    - Gate PASS + override active -> ATO-with-conditions
    """

    def decide(
        self,
        gate_decision: GateDecision,
        poam_items: list[POAMItem],
        overrides: list[dict[str, object]] | None = None,
    ) -> AuthorizationDecision:
        """Produce authorization decision."""
        now = datetime.now(timezone.utc)
        valid_until = (now + timedelta(days=90)).strftime("%Y-%m-%d")

        # Gate BLOCK -> DATO
        if not gate_decision.passed:
            return AuthorizationDecision(
                decision="DATO",
                risk_level="unacceptable",
                conditions=[],
                authorizer="automated-gate",
                timestamp=now.isoformat(),
                valid_until=valid_until,
                reasoning=f"Gate blocked: {gate_decision.reason}",
            )

        conditions: list[str] = []

        # Open POA&M items -> conditions
        open_items = [p for p in poam_items if p.status in ("open", "in-progress")]
        for item in open_items:
            conditions.append(
                f"{item.id}: {item.weakness} (deadline: {item.scheduled_completion})"
            )

        # Active overrides -> conditions
        if overrides:
            for ovr in overrides:
                ovr_id = ovr.get("id", "unknown")
                conditions.append(
                    f"Override {ovr_id}: deferred scan must complete per SLA"
                )

        if conditions:
            return AuthorizationDecision(
                decision="ATO-with-conditions",
                risk_level="conditionally-acceptable",
                conditions=conditions,
                authorizer="automated-gate",
                timestamp=now.isoformat(),
                valid_until=valid_until,
                reasoning="Gate passed but open POA&M items or active overrides require remediation",
            )

        return AuthorizationDecision(
            decision="ATO",
            risk_level="acceptable",
            conditions=[],
            authorizer="automated-gate",
            timestamp=now.isoformat(),
            valid_until=valid_until,
            reasoning="Gate passed with no outstanding risks",
        )
