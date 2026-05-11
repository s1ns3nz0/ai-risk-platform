"""Tests for Security Assessment Report (SAR) generator."""

from __future__ import annotations

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.controls.repository import ControlsRepository
from orchestrator.rmf.models import SP80030Report
from orchestrator.rmf.sar import SARGenerator
from orchestrator.types import Finding, GateDecision, RiskTier


# --- Helpers ---


def _make_controls_repo() -> ControlsRepository:
    """Load the real controls repository (102 controls)."""
    repo = ControlsRepository(
        baselines_dir="controls/baselines",
        tier_mappings_path="controls/tier-mappings.yaml",
    )
    repo.load_all()
    return repo


def _make_control(
    control_id: str = "PCI-DSS-6.3.1",
    title: str = "SAST Scanning",
    framework: str = "pci-dss-4.0",
    scanner: str = "semgrep",
) -> Control:
    return Control(
        id=control_id,
        title=title,
        framework=framework,
        description="Test control",
        verification_methods=[
            VerificationMethod(scanner=scanner),
        ],
        applicable_tiers=[RiskTier.CRITICAL, RiskTier.HIGH],
    )


def _make_gate_decision(passed: bool = True) -> GateDecision:
    return GateDecision(
        passed=passed,
        reason="All thresholds passed" if passed else "critical_findings > 0",
        threshold_results=[],
        findings_count={"critical": 0, "high": 0, "medium": 0, "low": 0},
    )


def _make_risk_report() -> SP80030Report:
    return SP80030Report(
        report_id="RA-SP800-30-2026-0503-001",
        product="payment-api",
        generated_at="2026-05-03T12:00:00Z",
        mode="static",
        methodology="NIST SP 800-30 Rev 1",
        scope="payment-api full assessment",
        risk_model="semi-quantitative, threat-oriented",
        assumptions=["Internet-facing service"],
        cia_impact_levels={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
        threat_sources=[],
        threat_events=[],
        likelihood_assessments=[],
        impact_assessments=[],
        risk_determinations=[],
        executive_summary="Test summary",
        risk_responses=[],
    )


def _mini_repo_with_controls(controls: list[Control]) -> ControlsRepository:
    """Create a ControlsRepository stub with specific controls."""
    repo = ControlsRepository.__new__(ControlsRepository)
    repo.controls = {c.id: c for c in controls}
    repo._tier_mappings = {}
    repo._framework_controls = {}
    return repo


# --- Tests ---


def test_sar_has_all_controls() -> None:
    """SAR should assess all 102 controls from the repository."""
    repo = _make_controls_repo()
    gen = SARGenerator(repo)

    sar = gen.generate(
        product="payment-api",
        findings=[],
        gate_decision=_make_gate_decision(passed=True),
    )

    assert sar.total_controls == 102
    assert len(sar.control_assessments) == 102


def test_satisfied_when_scanner_ran_no_issues() -> None:
    """Control with scanner findings but 0 issues -> satisfied."""
    ctrl = _make_control(control_id="PCI-DSS-6.3.1", scanner="semgrep")
    repo = _mini_repo_with_controls([ctrl])
    gen = SARGenerator(repo)

    # Finding from semgrep but severity=info (informational, not an issue)
    # Actually, "satisfied" means scanner ran and found NO issues for this control.
    # We simulate by having a finding from semgrep on a DIFFERENT control.
    # The control PCI-DSS-6.3.1 has semgrep as verification method.
    # We need a finding from semgrep that does NOT map to this control.
    findings = [
        Finding(
            source="semgrep",
            rule_id="some-other-rule",
            severity="low",
            file="src/other.py",
            line=1,
            message="Some other issue",
            control_ids=["OTHER-CTRL"],
            product="payment-api",
        ),
    ]

    sar = gen.generate(
        product="payment-api",
        findings=findings,
        gate_decision=_make_gate_decision(passed=True),
    )

    assessment = sar.control_assessments[0]
    assert assessment.control_id == "PCI-DSS-6.3.1"
    assert assessment.status == "satisfied"
    assert assessment.evidence_type == "automated"
    assert assessment.findings_count == 0


def test_other_than_satisfied_when_issues_found() -> None:
    """Control with findings flagging issues -> other-than-satisfied."""
    ctrl = _make_control(control_id="PCI-DSS-6.3.1", scanner="semgrep")
    repo = _mini_repo_with_controls([ctrl])
    gen = SARGenerator(repo)

    findings = [
        Finding(
            source="semgrep",
            rule_id="sql-injection",
            severity="high",
            file="src/api/export.py",
            line=42,
            message="SQL injection detected",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
        ),
    ]

    sar = gen.generate(
        product="payment-api",
        findings=findings,
        gate_decision=_make_gate_decision(passed=False),
    )

    assessment = sar.control_assessments[0]
    assert assessment.control_id == "PCI-DSS-6.3.1"
    assert assessment.status == "other-than-satisfied"
    assert assessment.evidence_type == "automated"
    assert assessment.findings_count == 1
    assert "1 high" in assessment.findings_summary


def test_not_assessed_when_no_scanner_ran() -> None:
    """Control with no evidence from any scanner -> not-assessed."""
    ctrl = _make_control(control_id="PCI-DSS-6.3.1", scanner="semgrep")
    repo = _mini_repo_with_controls([ctrl])
    gen = SARGenerator(repo)

    # No findings at all — semgrep never ran
    sar = gen.generate(
        product="payment-api",
        findings=[],
        gate_decision=_make_gate_decision(passed=True),
    )

    assessment = sar.control_assessments[0]
    assert assessment.control_id == "PCI-DSS-6.3.1"
    assert assessment.status == "not-assessed"
    assert assessment.evidence_type == "none"


def test_not_assessed_when_no_verification_methods() -> None:
    """Control with no verification_methods -> not-assessed (manual only)."""
    ctrl = Control(
        id="FISC-manual",
        title="Manual control",
        framework="fisc-safety",
        description="Requires manual review",
        verification_methods=[],
        applicable_tiers=[RiskTier.CRITICAL],
    )
    repo = _mini_repo_with_controls([ctrl])
    gen = SARGenerator(repo)

    sar = gen.generate(
        product="payment-api",
        findings=[],
        gate_decision=_make_gate_decision(passed=True),
    )

    assessment = sar.control_assessments[0]
    assert assessment.status == "not-assessed"
    assert assessment.assessor == "manual review required"


def test_coverage_percentage() -> None:
    """Coverage = satisfied / total."""
    controls = [
        _make_control(control_id="C1", scanner="semgrep"),
        _make_control(control_id="C2", scanner="checkov"),
        _make_control(control_id="C3", scanner="grype"),
        _make_control(control_id="C4", scanner="gitleaks"),
    ]
    repo = _mini_repo_with_controls(controls)
    gen = SARGenerator(repo)

    # semgrep and checkov ran (findings exist from those scanners),
    # but only C2 has issues. C1 is satisfied (semgrep ran, no issues for C1).
    findings = [
        Finding(
            source="semgrep",
            rule_id="clean-rule",
            severity="info",
            file="src/clean.py",
            line=1,
            message="Clean",
            control_ids=["OTHER"],
            product="payment-api",
        ),
        Finding(
            source="checkov",
            rule_id="CKV_AWS_19",
            severity="high",
            file="terraform/s3.tf",
            line=5,
            message="S3 without encryption",
            control_ids=["C2"],
            product="payment-api",
        ),
    ]

    sar = gen.generate(
        product="payment-api",
        findings=findings,
        gate_decision=_make_gate_decision(passed=True),
    )

    # C1: semgrep ran, no issues -> satisfied
    # C2: checkov ran, issues found -> other-than-satisfied
    # C3: grype never ran -> not-assessed
    # C4: gitleaks never ran -> not-assessed
    assert sar.satisfied == 1
    assert sar.other_than_satisfied == 1
    assert sar.not_assessed == 2
    assert sar.coverage_percentage == 25.0  # 1/4 = 25%


def test_authorization_recommendation_ato() -> None:
    """Gate PASS -> ATO recommendation."""
    repo = _mini_repo_with_controls([_make_control()])
    gen = SARGenerator(repo)

    # semgrep ran, no issues for the control
    findings = [
        Finding(
            source="semgrep",
            rule_id="clean",
            severity="info",
            file="x.py",
            line=1,
            message="ok",
            control_ids=["OTHER"],
            product="payment-api",
        ),
    ]

    sar = gen.generate(
        product="payment-api",
        findings=findings,
        gate_decision=_make_gate_decision(passed=True),
    )

    assert sar.authorization_recommendation == "ATO"
    assert sar.overall_risk == "acceptable"


def test_authorization_recommendation_dato() -> None:
    """Gate BLOCK -> DATO recommendation."""
    repo = _mini_repo_with_controls([_make_control()])
    gen = SARGenerator(repo)

    findings = [
        Finding(
            source="semgrep",
            rule_id="sqli",
            severity="critical",
            file="x.py",
            line=1,
            message="SQL injection",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
        ),
    ]

    sar = gen.generate(
        product="payment-api",
        findings=findings,
        gate_decision=_make_gate_decision(passed=False),
    )

    assert sar.authorization_recommendation == "DATO"
    assert sar.overall_risk == "unacceptable"


def test_sar_links_risk_report() -> None:
    """SAR should reference the SP 800-30 report ID when provided."""
    repo = _mini_repo_with_controls([_make_control()])
    gen = SARGenerator(repo)
    risk_report = _make_risk_report()

    sar = gen.generate(
        product="payment-api",
        findings=[],
        gate_decision=_make_gate_decision(passed=True),
        risk_report=risk_report,
    )

    assert sar.risk_assessment_id == "RA-SP800-30-2026-0503-001"


def test_sar_report_id_format() -> None:
    """SAR report ID should follow SAR-YYYY-MMDD-NNN format."""
    repo = _mini_repo_with_controls([_make_control()])
    gen = SARGenerator(repo)

    sar = gen.generate(
        product="payment-api",
        findings=[],
        gate_decision=_make_gate_decision(passed=True),
    )

    assert sar.report_id.startswith("SAR-")
    parts = sar.report_id.split("-")
    assert len(parts) == 4
    assert len(parts[1]) == 4  # YYYY
    assert len(parts[2]) == 4  # MMDD
