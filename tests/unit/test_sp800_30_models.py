"""Tests for SP 800-30 Rev 1 risk assessment data models."""

from __future__ import annotations

from orchestrator.rmf.models import (
    ImpactAssessment,
    LikelihoodAssessment,
    RiskDetermination,
    RiskResponse,
    SP80030Report,
    ThreatEvent,
    ThreatSource,
)


def _make_threat_source(**overrides: object) -> ThreatSource:
    defaults: dict[str, object] = {
        "id": "TS-ADV-001",
        "type": "adversarial",
        "name": "External attacker",
        "capability": "high",
        "intent": "Financial gain via cardholder data theft",
        "targeting": "Targeted — known payment processor",
    }
    defaults.update(overrides)
    return ThreatSource(**defaults)  # type: ignore[arg-type]


def _make_threat_event(**overrides: object) -> ThreatEvent:
    defaults: dict[str, object] = {
        "id": "TE-001",
        "description": "SQL injection via payment export endpoint",
        "source_id": "TS-ADV-001",
        "mitre_technique": "T1190",
        "relevance": "confirmed",
        "cve_id": "CVE-2025-12345",
        "target_component": "sqlalchemy 1.4.0",
    }
    defaults.update(overrides)
    return ThreatEvent(**defaults)  # type: ignore[arg-type]


def _make_likelihood(**overrides: object) -> LikelihoodAssessment:
    defaults: dict[str, object] = {
        "initiation_likelihood": "high",
        "impact_likelihood": "high",
        "overall_likelihood": "high",
        "epss_score": 0.45,
        "predisposing_conditions": ["internet-facing", "PCI scope"],
        "evidence": "EPSS 0.45, internet-facing API with PCI data",
    }
    defaults.update(overrides)
    return LikelihoodAssessment(**defaults)  # type: ignore[arg-type]


def _make_impact(**overrides: object) -> ImpactAssessment:
    defaults: dict[str, object] = {
        "impact_type": "harm to operations",
        "cia_impact": {
            "confidentiality": "high",
            "integrity": "high",
            "availability": "moderate",
        },
        "severity": "high",
        "compliance_impact": ["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
        "business_impact": "Cardholder data exposure, PCI non-compliance",
        "evidence": "PCI-scoped API handling financial transactions",
    }
    defaults.update(overrides)
    return ImpactAssessment(**defaults)  # type: ignore[arg-type]


def _make_risk_determination(**overrides: object) -> RiskDetermination:
    defaults: dict[str, object] = {
        "threat_event_id": "TE-001",
        "likelihood": "high",
        "impact": "high",
        "risk_level": "high",
        "risk_score": 81.0,
    }
    defaults.update(overrides)
    return RiskDetermination(**defaults)  # type: ignore[arg-type]


def _make_risk_response(**overrides: object) -> RiskResponse:
    defaults: dict[str, object] = {
        "risk_determination_id": "TE-001",
        "response_type": "mitigate",
        "description": "Upgrade sqlalchemy to patched version",
        "milestones": ["Identify affected services", "Apply patch", "Verify fix"],
        "deadline": "2026-06-01",
        "responsible": "Security Engineer",
    }
    defaults.update(overrides)
    return RiskResponse(**defaults)  # type: ignore[arg-type]


def _make_report(**overrides: object) -> SP80030Report:
    defaults: dict[str, object] = {
        "report_id": "RA-SP800-30-2026-0503-001",
        "product": "payment-api",
        "generated_at": "2026-05-03T12:00:00+00:00",
        "mode": "static",
        "methodology": "NIST SP 800-30 Rev 1",
        "scope": "payment-api full stack including IaC and dependencies",
        "risk_model": "semi-quantitative, threat-oriented",
        "assumptions": ["All scanners ran successfully", "SBOM is complete"],
        "cia_impact_levels": {
            "confidentiality": "high",
            "integrity": "high",
            "availability": "moderate",
        },
        "threat_sources": [_make_threat_source()],
        "threat_events": [_make_threat_event()],
        "likelihood_assessments": [_make_likelihood()],
        "impact_assessments": [_make_impact()],
        "risk_determinations": [_make_risk_determination()],
        "executive_summary": "Payment API has 1 high-risk threat event.",
        "risk_responses": [_make_risk_response()],
        "recommendations": ["Upgrade sqlalchemy", "Add WAF rule for SQLi"],
        "reassessment_triggers": [
            "New critical CVE in dependency",
            "Architecture change",
        ],
        "next_review_date": "2026-08-03",
    }
    defaults.update(overrides)
    return SP80030Report(**defaults)  # type: ignore[arg-type]


# --- Tests ---


class TestThreatSource:
    def test_threat_source_creation(self) -> None:
        ts = _make_threat_source()
        assert ts.id == "TS-ADV-001"
        assert ts.type == "adversarial"
        assert ts.name == "External attacker"
        assert ts.capability == "high"
        assert ts.intent == "Financial gain via cardholder data theft"
        assert ts.targeting == "Targeted — known payment processor"

    def test_non_adversarial_source(self) -> None:
        ts = _make_threat_source(
            id="TS-STR-001",
            type="structural",
            name="System failure",
            intent="",
            targeting="",
        )
        assert ts.type == "structural"
        assert ts.intent == ""


class TestThreatEvent:
    def test_threat_event_with_cve(self) -> None:
        te = _make_threat_event()
        assert te.id == "TE-001"
        assert te.cve_id == "CVE-2025-12345"
        assert te.mitre_technique == "T1190"
        assert te.source_id == "TS-ADV-001"
        assert te.target_component == "sqlalchemy 1.4.0"
        assert te.relevance == "confirmed"

    def test_threat_event_without_cve(self) -> None:
        te = _make_threat_event(cve_id="", description="Brute force login")
        assert te.cve_id == ""
        assert te.description == "Brute force login"


class TestLikelihoodAssessment:
    def test_likelihood_with_epss(self) -> None:
        la = _make_likelihood()
        assert la.epss_score == 0.45
        assert la.overall_likelihood == "high"
        assert "internet-facing" in la.predisposing_conditions
        assert "PCI scope" in la.predisposing_conditions
        assert la.evidence != ""

    def test_likelihood_without_epss(self) -> None:
        la = _make_likelihood(epss_score=None, overall_likelihood="moderate")
        assert la.epss_score is None
        assert la.overall_likelihood == "moderate"


class TestRiskDetermination:
    """SP 800-30 Table G-10: likelihood × impact → risk level."""

    def test_risk_determination_matrix(self) -> None:
        rd = _make_risk_determination()
        assert rd.likelihood == "high"
        assert rd.impact == "high"
        assert rd.risk_level == "high"
        assert rd.risk_score == 81.0
        assert rd.threat_event_id == "TE-001"

    def test_low_risk_determination(self) -> None:
        rd = _make_risk_determination(
            likelihood="low",
            impact="low",
            risk_level="low",
            risk_score=16.0,
        )
        assert rd.risk_level == "low"
        assert rd.risk_score == 16.0


class TestRiskResponse:
    def test_risk_response_types(self) -> None:
        valid_types = ["accept", "avoid", "mitigate", "share", "transfer"]
        for rt in valid_types:
            rr = _make_risk_response(response_type=rt)
            assert rr.response_type == rt

    def test_risk_response_milestones(self) -> None:
        rr = _make_risk_response()
        assert len(rr.milestones) == 3
        assert rr.deadline == "2026-06-01"
        assert rr.responsible == "Security Engineer"


class TestSP80030Report:
    def test_sp800_30_report_has_all_phases(self) -> None:
        report = _make_report()

        # Phase 1: Prepare
        assert report.scope != ""
        assert report.risk_model == "semi-quantitative, threat-oriented"
        assert len(report.assumptions) > 0
        assert "confidentiality" in report.cia_impact_levels

        # Phase 2: Conduct
        assert len(report.threat_sources) == 1
        assert len(report.threat_events) == 1
        assert len(report.likelihood_assessments) == 1
        assert len(report.impact_assessments) == 1
        assert len(report.risk_determinations) == 1

        # Phase 3: Communicate
        assert report.executive_summary != ""
        assert len(report.risk_responses) == 1
        assert len(report.recommendations) == 2

        # Phase 4: Maintain
        assert len(report.reassessment_triggers) == 2
        assert report.next_review_date == "2026-08-03"

        # Metadata
        assert report.report_id.startswith("RA-SP800-30-")
        assert report.methodology == "NIST SP 800-30 Rev 1"
        assert report.mode == "static"

    def test_report_id_format(self) -> None:
        report = _make_report()
        assert report.report_id == "RA-SP800-30-2026-0503-001"

    def test_report_ai_mode(self) -> None:
        report = _make_report(mode="ai")
        assert report.mode == "ai"
