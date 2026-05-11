"""Tests for dashboard exporter — TDD: write tests first."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestrator.exporters.dashboard import export_dashboard
from orchestrator.rmf.models import (
    ImpactAssessment,
    LikelihoodAssessment,
    RiskDetermination,
    RiskResponse,
    SP80030Report,
    ThreatEvent,
    ThreatSource,
)
from orchestrator.rmf.poam import AuthorizationDecision, POAMItem
from orchestrator.rmf.sar import ControlAssessment, SecurityAssessmentReport


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def sp800_report() -> SP80030Report:
    return SP80030Report(
        report_id="RA-SP800-30-2026-0504-001",
        product="payment-api",
        generated_at="2026-05-04T12:00:00+00:00",
        mode="ai",
        methodology="NIST SP 800-30 Rev 1",
        scope="payment-api full stack",
        risk_model="semi-quantitative, threat-oriented",
        assumptions=["Internet-facing service"],
        cia_impact_levels={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
        threat_sources=[
            ThreatSource(
                id="TS-001",
                type="adversarial",
                name="External attacker",
                capability="high",
                intent="high",
                targeting="moderate",
            ),
        ],
        threat_events=[
            ThreatEvent(
                id="TE-001",
                description="SQL injection via export endpoint",
                source_id="TS-001",
                mitre_technique="T1190",
                relevance="confirmed",
                cve_id="",
                target_component="src/api/export.py",
            ),
        ],
        likelihood_assessments=[
            LikelihoodAssessment(
                initiation_likelihood="high",
                impact_likelihood="high",
                overall_likelihood="high",
                epss_score=0.85,
                predisposing_conditions=["internet-facing", "PCI scope"],
                evidence="Confirmed SQLi vulnerability",
            ),
        ],
        impact_assessments=[
            ImpactAssessment(
                impact_type="harm to operations",
                cia_impact={"confidentiality": "high", "integrity": "high", "availability": "low"},
                severity="high",
                compliance_impact=["PCI-DSS-6.3.1"],
                business_impact="Cardholder data exposure",
                evidence="PCI scope data at risk",
            ),
        ],
        risk_determinations=[
            RiskDetermination(
                threat_event_id="TE-001",
                likelihood="high",
                impact="high",
                risk_level="high",
                risk_score=75.0,
            ),
        ],
        executive_summary="High risk due to confirmed SQL injection in PCI scope.",
        risk_responses=[
            RiskResponse(
                risk_determination_id="TE-001",
                response_type="mitigate",
                description="Parameterize SQL queries",
                milestones=["Identify fix", "Deploy"],
                deadline="2026-06-04",
                responsible="security-engineer",
            ),
        ],
        recommendations=["Parameterize all SQL queries"],
    )


@pytest.fixture()
def sar() -> SecurityAssessmentReport:
    return SecurityAssessmentReport(
        report_id="SAR-2026-0504-001",
        product="payment-api",
        generated_at="2026-05-04T12:00:00+00:00",
        system_description="Security assessment for payment-api",
        assessment_methodology="Automated scanning + SP 800-30 risk assessment",
        control_assessments=[
            ControlAssessment(
                control_id="PCI-DSS-6.3.1",
                title="Secure coding",
                framework="PCI-DSS-4.0",
                status="other-than-satisfied",
                evidence_type="automated",
                assessor="semgrep",
                findings_count=3,
                findings_summary="Found 3 issue(s): 1 critical, 2 high",
                risk_level="critical",
            ),
            ControlAssessment(
                control_id="PCI-DSS-3.5.1",
                title="Key management",
                framework="PCI-DSS-4.0",
                status="satisfied",
                evidence_type="automated",
                assessor="gitleaks",
                findings_count=0,
                findings_summary="No issues found",
                risk_level="none",
            ),
            ControlAssessment(
                control_id="FISC-実119",
                title="IaC security",
                framework="FISC",
                status="not-assessed",
                evidence_type="none",
                assessor="manual review required",
                findings_count=0,
                findings_summary="Scanner(s) did not run",
                risk_level="unknown",
            ),
        ],
        total_controls=3,
        satisfied=1,
        other_than_satisfied=1,
        not_assessed=1,
        coverage_percentage=33.3,
        risk_assessment_id="RA-SP800-30-2026-0504-001",
        overall_risk="unacceptable",
        authorization_recommendation="DATO",
    )


@pytest.fixture()
def poam_items() -> list[POAMItem]:
    return [
        POAMItem(
            id="POAM-2026-0504-001",
            weakness="SQL injection in export endpoint",
            control_id="PCI-DSS-6.3.1",
            source="semgrep",
            finding_id="python.django.security.injection.sql-injection",
            severity="critical",
            risk_level="very-high",
            status="open",
            milestones=[
                {"description": "Identify fix", "target_date": "2026-05-05", "status": "open"},
                {"description": "Deploy to production", "target_date": "2026-05-11", "status": "open"},
            ],
            scheduled_completion="2026-05-11",
            responsible="security-engineer",
            cost_estimate="high",
            finding_evidence="findings.jsonl",
            override_id="",
        ),
        POAMItem(
            id="POAM-2026-0504-002",
            weakness="Outdated cryptography library",
            control_id="PCI-DSS-6.3.1",
            source="grype",
            finding_id="CVE-2024-12345",
            severity="high",
            risk_level="high",
            status="open",
            milestones=[
                {"description": "Identify fix", "target_date": "2026-05-05", "status": "open"},
                {"description": "Deploy to production", "target_date": "2026-06-03", "status": "open"},
            ],
            scheduled_completion="2026-06-03",
            responsible="security-engineer",
            cost_estimate="moderate",
            finding_evidence="findings.jsonl",
            override_id="",
        ),
    ]


@pytest.fixture()
def authorization() -> AuthorizationDecision:
    return AuthorizationDecision(
        decision="DATO",
        risk_level="unacceptable",
        conditions=[],
        authorizer="automated-gate",
        timestamp="2026-05-04T12:00:00+00:00",
        valid_until="2026-08-04",
        reasoning="Gate blocked: critical findings in PCI scope",
    )


@pytest.fixture()
def pipeline_metadata() -> dict:
    return {
        "scanners": ["semgrep", "grype", "checkov", "gitleaks"],
        "ai_model": "jp.anthropic.claude-sonnet-4-6",
        "duration_seconds": 35.2,
    }


# ── Tests ─────────────────────────────────────────────────────────────


def test_export_creates_5_files(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
    pipeline_metadata: dict,
) -> None:
    """output_dir/dashboard/ 하위 5개 파일 생성 확인."""
    paths = export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path), pipeline_metadata)
    dashboard_dir = tmp_path / "dashboard"
    expected = {"index.json", "sp800-30.json", "sar.json", "poam.json", "authorization.json"}
    assert {p.name for p in dashboard_dir.iterdir()} == expected
    assert len(paths) == 5


def test_index_json_under_5kb(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """index.json 파일 크기 < 5KB."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    index_path = tmp_path / "dashboard" / "index.json"
    assert index_path.stat().st_size < 5 * 1024


def test_index_contains_risk_posture(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """index.json에 risk_distribution, overall 필드 존재."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    data = json.loads((tmp_path / "dashboard" / "index.json").read_text())
    assert "risk_posture" in data
    assert "overall" in data["risk_posture"]
    assert "risk_distribution" in data["risk_posture"]


def test_index_contains_gate_decision(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """gate.decision 필드 == authorization.decision."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    data = json.loads((tmp_path / "dashboard" / "index.json").read_text())
    assert data["gate"]["decision"] == authorization.decision


def test_index_contains_sar_summary(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """sar_summary.total_controls == sar.total_controls."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    data = json.loads((tmp_path / "dashboard" / "index.json").read_text())
    assert data["sar_summary"]["total_controls"] == sar.total_controls


def test_index_contains_poam_summary(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """poam_summary.total_items == len(poam_items)."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    data = json.loads((tmp_path / "dashboard" / "index.json").read_text())
    assert data["poam_summary"]["total_items"] == len(poam_items)


def test_sp800_30_json_has_threat_sources(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """sp800-30.json에 threat_sources 배열 존재."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    data = json.loads((tmp_path / "dashboard" / "sp800-30.json").read_text())
    assert "threat_sources" in data
    assert isinstance(data["threat_sources"], list)
    assert len(data["threat_sources"]) == 1


def test_sar_json_has_control_assessments(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """sar.json에 control_assessments 배열 존재."""
    export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    data = json.loads((tmp_path / "dashboard" / "sar.json").read_text())
    assert "control_assessments" in data
    assert isinstance(data["control_assessments"], list)
    assert len(data["control_assessments"]) == 3


def test_export_returns_file_paths(
    tmp_path: Path,
    sp800_report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
) -> None:
    """반환된 경로 리스트가 5개이고 모두 존재."""
    paths = export_dashboard(sp800_report, sar, poam_items, authorization, str(tmp_path))
    assert len(paths) == 5
    for p in paths:
        assert Path(p).exists()
