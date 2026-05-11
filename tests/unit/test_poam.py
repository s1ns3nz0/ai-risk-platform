"""Tests for POA&M and Authorization Engine."""

from __future__ import annotations

from orchestrator.rmf.models import RiskDetermination, RiskResponse, SP80030Report
from orchestrator.rmf.poam import (
    AuthorizationEngine,
    POAMGenerator,
    POAMItem,
)
from orchestrator.types import Finding, GateDecision


# --- Helpers ---


def _make_finding(
    severity: str = "critical",
    control_id: str = "PCI-DSS-6.3.1",
    rule_id: str = "sql-injection",
    source: str = "semgrep",
) -> Finding:
    return Finding(
        source=source,
        rule_id=rule_id,
        severity=severity,
        file="src/api/export.py",
        line=42,
        message=f"{severity} issue",
        control_ids=[control_id],
        product="payment-api",
    )


def _make_gate_decision(passed: bool = True) -> GateDecision:
    return GateDecision(
        passed=passed,
        reason="All thresholds passed" if passed else "critical_findings > 0",
        threshold_results=[],
        findings_count={"critical": 0, "high": 0, "medium": 0, "low": 0},
    )


def _make_risk_report(risk_level: str = "high") -> SP80030Report:
    return SP80030Report(
        report_id="RA-SP800-30-2026-0503-001",
        product="payment-api",
        generated_at="2026-05-03T12:00:00Z",
        mode="static",
        methodology="NIST SP 800-30 Rev 1",
        scope="payment-api full assessment",
        risk_model="semi-quantitative, threat-oriented",
        assumptions=["Internet-facing service"],
        cia_impact_levels={
            "confidentiality": "high",
            "integrity": "high",
            "availability": "moderate",
        },
        threat_sources=[],
        threat_events=[],
        likelihood_assessments=[],
        impact_assessments=[],
        risk_determinations=[
            RiskDetermination(
                threat_event_id="TE-001",
                likelihood=risk_level,
                impact=risk_level,
                risk_level=risk_level,
                risk_score=80.0,
            ),
        ],
        executive_summary="Test summary",
        risk_responses=[
            RiskResponse(
                risk_determination_id="TE-001",
                response_type="mitigate",
                description="Apply patches",
                milestones=["Identify fix", "Deploy"],
                deadline="2026-06-03",
                responsible="dev-team",
            ),
        ],
    )


# --- POA&M Generator Tests ---


def test_critical_finding_creates_poam_item() -> None:
    """Critical finding -> POA&M item with 7-day deadline."""
    gen = POAMGenerator()
    findings = [_make_finding(severity="critical")]

    items = gen.generate(findings=findings)

    assert len(items) == 1
    item = items[0]
    assert item.severity == "critical"
    assert item.status == "open"
    # 7-day deadline for critical
    assert item.scheduled_completion != ""


def test_high_finding_creates_poam_item() -> None:
    """High finding -> POA&M item with 30-day deadline."""
    gen = POAMGenerator()
    findings = [_make_finding(severity="high")]

    items = gen.generate(findings=findings)

    assert len(items) == 1
    item = items[0]
    assert item.severity == "high"
    assert item.status == "open"


def test_poam_has_milestones() -> None:
    """Each POA&M item should have 4 milestones."""
    gen = POAMGenerator()
    findings = [_make_finding(severity="critical")]

    items = gen.generate(findings=findings)

    assert len(items) == 1
    item = items[0]
    assert len(item.milestones) == 4
    # Verify milestone descriptions
    descriptions = [m["description"] for m in item.milestones]
    assert "Identify fix" in descriptions[0]
    assert "Implement fix" in descriptions[1]
    assert "Verify in staging" in descriptions[2]
    assert "Deploy to production" in descriptions[3]


def test_poam_links_to_control() -> None:
    """POA&M item should reference the control_id."""
    gen = POAMGenerator()
    findings = [_make_finding(control_id="ASVS-V5.3.4")]

    items = gen.generate(findings=findings)

    assert len(items) == 1
    assert items[0].control_id == "ASVS-V5.3.4"
    assert items[0].source == "semgrep"
    assert items[0].finding_id == "sql-injection"


def test_gate_pass_no_risk_ato() -> None:
    """Gate PASS + no open POA&M items -> ATO."""
    engine = AuthorizationEngine()
    gate = _make_gate_decision(passed=True)

    decision = engine.decide(
        gate_decision=gate,
        poam_items=[],
    )

    assert decision.decision == "ATO"
    assert decision.risk_level == "acceptable"


def test_gate_block_dato() -> None:
    """Gate BLOCK -> DATO."""
    engine = AuthorizationEngine()
    gate = _make_gate_decision(passed=False)

    decision = engine.decide(
        gate_decision=gate,
        poam_items=[],
    )

    assert decision.decision == "DATO"
    assert decision.risk_level == "unacceptable"


def test_gate_pass_with_poam_ato_conditions() -> None:
    """Gate PASS + open POA&M items -> ATO-with-conditions."""
    engine = AuthorizationEngine()
    gate = _make_gate_decision(passed=True)

    poam_items = [
        POAMItem(
            id="POAM-2026-0503-001",
            weakness="SQL injection in export endpoint",
            control_id="PCI-DSS-6.3.1",
            source="semgrep",
            finding_id="sql-injection",
            severity="high",
            risk_level="high",
            status="open",
            milestones=[],
            scheduled_completion="2026-06-03",
            responsible="dev-team",
            cost_estimate="moderate",
            finding_evidence="findings.jsonl",
            override_id="",
        ),
    ]

    decision = engine.decide(
        gate_decision=gate,
        poam_items=poam_items,
    )

    assert decision.decision == "ATO-with-conditions"
    assert len(decision.conditions) > 0
    assert "POAM-2026-0503-001" in decision.conditions[0]


def test_override_creates_conditional_poam() -> None:
    """Override present -> ATO-with-conditions + linked POA&M."""
    engine = AuthorizationEngine()
    gate = _make_gate_decision(passed=True)

    overrides = [
        {
            "id": "OVR-2026-0503-001",
            "product": "payment-api",
            "tier": "critical",
            "failed_scanners": ["grype"],
            "reason": "scanner_service_down",
        },
    ]

    decision = engine.decide(
        gate_decision=gate,
        poam_items=[],
        overrides=overrides,
    )

    assert decision.decision == "ATO-with-conditions"
    assert any("OVR-2026-0503-001" in c for c in decision.conditions)
