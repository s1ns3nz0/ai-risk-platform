"""Tests for risk-assess CLI command (RMF Step 5 CLI integration)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner

from orchestrator.cli import cli
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
from orchestrator.types import Finding, GateDecision, RiskTier


# --- Helpers ---


def _make_findings() -> list[Finding]:
    return [
        Finding(
            source="semgrep",
            rule_id="sql-injection",
            severity="critical",
            file="src/api/export.py",
            line=42,
            message="SQL injection detected",
            control_ids=["PCI-DSS-6.3.1"],
            product="payment-api",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-50782",
            severity="high",
            file="requirements.txt",
            line=0,
            message="cryptography < 42.0.0 vulnerable",
            control_ids=["PCI-DSS-6.3.1", "ASVS-V14.2.1"],
            product="payment-api",
            package="cryptography",
            installed_version="41.0.0",
            fixed_version="42.0.0",
        ),
        Finding(
            source="gitleaks",
            rule_id="aws-access-key",
            severity="critical",
            file="src/config.py",
            line=10,
            message="AWS access key detected",
            control_ids=["PCI-DSS-3.5.1"],
            product="payment-api",
        ),
    ]


def _make_gate_decision(passed: bool = False) -> GateDecision:
    return GateDecision(
        passed=passed,
        reason="critical_findings > 0" if not passed else "All thresholds passed",
        threshold_results=[],
        findings_count={"critical": 2, "high": 1, "medium": 0, "low": 0},
    )


def _make_sp800_30_report() -> SP80030Report:
    return SP80030Report(
        report_id="RA-SP800-30-2026-0503-001",
        product="payment-api",
        generated_at="2026-05-03T12:00:00Z",
        mode="static",
        methodology="NIST SP 800-30 Rev 1",
        scope="payment-api full stack",
        risk_model="semi-quantitative, threat-oriented",
        assumptions=["All scanners ran successfully"],
        cia_impact_levels={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
        threat_sources=[
            ThreatSource(
                id="TS-ADV-001", type="adversarial",
                name="External attacker", capability="very-high",
                intent="Financial gain", targeting="Targeted",
            ),
        ],
        threat_events=[
            ThreatEvent(
                id="TE-001", description="SQL injection",
                source_id="TS-ADV-001", mitre_technique="T1190",
                relevance="confirmed", cve_id="",
                target_component="src/api/export.py:42",
            ),
        ],
        likelihood_assessments=[
            LikelihoodAssessment(
                initiation_likelihood="very-high",
                impact_likelihood="very-high",
                overall_likelihood="very-high",
                epss_score=None,
                predisposing_conditions=["PCI scope"],
                evidence="Critical severity",
            ),
        ],
        impact_assessments=[
            ImpactAssessment(
                impact_type="harm to operations",
                cia_impact={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
                severity="very-high",
                compliance_impact=["PCI-DSS-6.3.1"],
                business_impact="Critical finding in PCI-scoped product",
                evidence="PCI control violated",
            ),
        ],
        risk_determinations=[
            RiskDetermination(
                threat_event_id="TE-001",
                likelihood="very-high",
                impact="very-high",
                risk_level="very-high",
                risk_score=92.16,
            ),
        ],
        executive_summary="Critical risk assessment for payment-api",
        risk_responses=[
            RiskResponse(
                risk_determination_id="TE-001",
                response_type="mitigate",
                description="Fix SQL injection",
                milestones=["Identify fix", "Deploy"],
                deadline="2026-05-10",
                responsible="Security Engineer",
            ),
        ],
        recommendations=["Immediately remediate all critical findings"],
    )


def _make_sar(authorization: str = "DATO") -> SecurityAssessmentReport:
    return SecurityAssessmentReport(
        report_id="SAR-2026-0503-001",
        product="payment-api",
        generated_at="2026-05-03T12:00:00Z",
        system_description="Security assessment for payment-api",
        assessment_methodology="Automated scanning + SP 800-30 risk assessment",
        control_assessments=[
            ControlAssessment(
                control_id="PCI-DSS-6.3.1",
                title="SAST Scanning",
                framework="pci-dss-4.0",
                status="other-than-satisfied",
                evidence_type="automated",
                assessor="semgrep",
                findings_count=1,
                findings_summary="Found 1 issue(s): 1 critical",
                risk_level="critical",
            ),
        ],
        total_controls=102,
        satisfied=18,
        other_than_satisfied=24,
        not_assessed=60,
        coverage_percentage=17.6,
        risk_assessment_id="RA-SP800-30-2026-0503-001",
        overall_risk="unacceptable" if authorization == "DATO" else "acceptable",
        authorization_recommendation=authorization,
    )


def _make_poam_items() -> list[POAMItem]:
    return [
        POAMItem(
            id="POAM-2026-0503-001",
            weakness="SQL injection detected",
            control_id="PCI-DSS-6.3.1",
            source="semgrep",
            finding_id="sql-injection",
            severity="critical",
            risk_level="very-high",
            status="open",
            milestones=[
                {"description": "Identify fix", "target_date": "2026-05-04", "status": "open"},
                {"description": "Implement fix", "target_date": "2026-05-06", "status": "open"},
                {"description": "Verify in staging", "target_date": "2026-05-08", "status": "open"},
                {"description": "Deploy to production", "target_date": "2026-05-10", "status": "open"},
            ],
            scheduled_completion="2026-05-10",
            responsible="security-engineer",
            cost_estimate="high",
            finding_evidence="findings.jsonl",
            override_id="",
        ),
    ]


def _make_authorization(decision: str = "DATO") -> AuthorizationDecision:
    return AuthorizationDecision(
        decision=decision,
        risk_level="unacceptable" if decision == "DATO" else "acceptable",
        conditions=[] if decision != "ATO-with-conditions" else ["POAM-2026-0503-001: resolve"],
        authorizer="automated-gate",
        timestamp="2026-05-03T12:00:00Z",
        valid_until="2026-08-01",
        reasoning="Gate blocked" if decision == "DATO" else "Gate passed",
    )


# Build a consolidated mock patcher for the full risk-assess pipeline
def _patch_risk_assess_pipeline(
    findings: list[Finding] | None = None,
    gate_passed: bool = False,
    authorization_decision: str = "DATO",
):
    """Return a dict of patches for the risk-assess pipeline."""
    findings = findings or _make_findings()
    gate = _make_gate_decision(passed=gate_passed)
    report = _make_sp800_30_report()
    sar = _make_sar("ATO" if gate_passed else "DATO")
    poam_items = _make_poam_items() if not gate_passed else []
    auth = _make_authorization(authorization_decision)

    patches = {
        "load_manifest": patch("orchestrator.cli.load_manifest"),
        "load_profile": patch("orchestrator.cli.load_profile"),
        "controls_repo": patch("orchestrator.cli.ControlsRepository"),
        "get_assessor": patch("orchestrator.cli.get_assessor"),
        "select_baseline": patch("orchestrator.cli.select_baseline"),
        "scanner_runner": patch("orchestrator.cli.ScannerRunner"),
        "control_mapper": patch("orchestrator.cli.ControlMapper"),
        "combined_gate": patch("orchestrator.gate.combined.CombinedGateEvaluator"),
        "threshold_eval": patch("orchestrator.cli.ThresholdEvaluator"),
        "opa_eval": patch("orchestrator.gate.opa.OpaEvaluator"),
        "jsonl_writer": patch("orchestrator.cli.JsonlWriter"),
        "static_pipeline": patch("orchestrator.cli.StaticRiskAssessmentPipeline"),
        "sar_generator": patch("orchestrator.cli.SARGenerator"),
        "poam_generator": patch("orchestrator.cli.POAMGenerator"),
        "auth_engine": patch("orchestrator.cli.AuthorizationEngine"),
    }

    def setup_mocks(mocks: dict[str, MagicMock]) -> None:
        # Manifest
        manifest = MagicMock()
        manifest.name = "payment-api"
        manifest.data_classification = ["PCI"]
        manifest.impact_levels = {"confidentiality": "high", "integrity": "high", "availability": "moderate"}
        mocks["load_manifest"].return_value = manifest

        # Profile
        profile = MagicMock()
        profile.frameworks = ["pci-dss-4.0", "asvs-5.0-L3"]
        mocks["load_profile"].return_value = profile

        # Controls repo
        repo_inst = MagicMock()
        mocks["controls_repo"].return_value = repo_inst

        # Assessor
        assessor = MagicMock()
        assessor.categorize.return_value = RiskTier.CRITICAL
        mocks["get_assessor"].return_value = assessor

        # Baseline
        mocks["select_baseline"].return_value = []

        # Scanners
        runner_inst = MagicMock()
        runner_inst.run_all.return_value = findings
        mocks["scanner_runner"].return_value = runner_inst

        # Gate
        gate_inst = MagicMock()
        gate_inst.evaluate.return_value = gate
        mocks["combined_gate"].return_value = gate_inst

        # JSONL
        mocks["jsonl_writer"].return_value = MagicMock()

        # Static pipeline
        pipeline_inst = MagicMock()
        pipeline_inst.run.return_value = report
        mocks["static_pipeline"].return_value = pipeline_inst

        # SAR
        sar_inst = MagicMock()
        sar_inst.generate.return_value = sar
        mocks["sar_generator"].return_value = sar_inst

        # POA&M
        poam_inst = MagicMock()
        poam_inst.generate.return_value = poam_items
        mocks["poam_generator"].return_value = poam_inst

        # Authorization
        auth_inst = MagicMock()
        auth_inst.decide.return_value = auth
        mocks["auth_engine"].return_value = auth_inst

    return patches, setup_mocks


# --- Tests ---


def test_risk_assess_help() -> None:
    """risk-assess --help should show usage information."""
    runner = CliRunner()
    result = runner.invoke(cli, ["risk-assess", "--help"])
    assert result.exit_code == 0
    assert "Run full NIST SP 800-30 risk assessment" in result.output
    assert "--product" in result.output
    assert "--trigger" in result.output
    assert "--format" in result.output


def test_risk_assess_produces_4_reports(tmp_path: Path) -> None:
    """risk-assess should produce 4 report files (SP 800-30, SAR, POA&M, Authorization)."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    patches, setup_mocks = _patch_risk_assess_pipeline(gate_passed=False, authorization_decision="DATO")

    mocks: dict[str, MagicMock] = {}
    with_contexts = []
    for name, p in patches.items():
        cm = p
        mock = cm.__enter__()
        mocks[name] = mock
        with_contexts.append(cm)

    try:
        setup_mocks(mocks)

        runner = CliRunner()
        result = runner.invoke(cli, [
            "risk-assess", "/fake/path",
            "--product", "payment-api",
            "--output", str(output_dir),
        ])

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Check 4 report files exist
        expected_files = [
            "sp800-30-payment-api.yaml",
            "sar-payment-api.yaml",
            "poam-payment-api.yaml",
            "authorization-payment-api.yaml",
        ]
        for fname in expected_files:
            fpath = output_dir / fname
            assert fpath.exists(), f"Missing report: {fname}"

        # Verify YAML is parseable
        for fname in expected_files:
            data = yaml.safe_load((output_dir / fname).read_text())
            assert data is not None, f"Empty report: {fname}"
    finally:
        for cm in with_contexts:
            cm.__exit__(None, None, None)


def test_risk_assess_static_mode(tmp_path: Path) -> None:
    """risk-assess without BEDROCK_MODEL_ID should use static mode."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    patches, setup_mocks = _patch_risk_assess_pipeline(gate_passed=True, authorization_decision="ATO")

    mocks: dict[str, MagicMock] = {}
    with_contexts = []
    for name, p in patches.items():
        cm = p
        mock = cm.__enter__()
        mocks[name] = mock
        with_contexts.append(cm)

    try:
        setup_mocks(mocks)

        runner = CliRunner()
        result = runner.invoke(cli, [
            "risk-assess", "/fake/path",
            "--product", "payment-api",
            "--output", str(output_dir),
        ])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert "static mode" in result.output.lower() or "static" in result.output.lower()

        # Static pipeline was used (not Bedrock)
        mocks["static_pipeline"].return_value.run.assert_called_once()
    finally:
        for cm in with_contexts:
            cm.__exit__(None, None, None)


def test_risk_assess_authorization_dato(tmp_path: Path) -> None:
    """Gate BLOCK should produce DATO authorization."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    patches, setup_mocks = _patch_risk_assess_pipeline(gate_passed=False, authorization_decision="DATO")

    mocks: dict[str, MagicMock] = {}
    with_contexts = []
    for name, p in patches.items():
        cm = p
        mock = cm.__enter__()
        mocks[name] = mock
        with_contexts.append(cm)

    try:
        setup_mocks(mocks)

        runner = CliRunner()
        result = runner.invoke(cli, [
            "risk-assess", "/fake/path",
            "--product", "payment-api",
            "--output", str(output_dir),
        ])

        assert result.exit_code == 0
        assert "DATO" in result.output

        # Check authorization report content
        auth_data = yaml.safe_load((output_dir / "authorization-payment-api.yaml").read_text())
        assert auth_data["decision"] == "DATO"
    finally:
        for cm in with_contexts:
            cm.__exit__(None, None, None)


def test_risk_assess_authorization_ato(tmp_path: Path) -> None:
    """Gate PASS with no open POA&M should produce ATO authorization."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    patches, setup_mocks = _patch_risk_assess_pipeline(gate_passed=True, authorization_decision="ATO")

    mocks: dict[str, MagicMock] = {}
    with_contexts = []
    for name, p in patches.items():
        cm = p
        mock = cm.__enter__()
        mocks[name] = mock
        with_contexts.append(cm)

    try:
        setup_mocks(mocks)

        runner = CliRunner()
        result = runner.invoke(cli, [
            "risk-assess", "/fake/path",
            "--product", "payment-api",
            "--output", str(output_dir),
        ])

        assert result.exit_code == 0
        assert "ATO" in result.output

        auth_data = yaml.safe_load((output_dir / "authorization-payment-api.yaml").read_text())
        assert auth_data["decision"] == "ATO"
    finally:
        for cm in with_contexts:
            cm.__exit__(None, None, None)


def test_risk_assess_poam_items_created(tmp_path: Path) -> None:
    """POA&M items should be created from findings."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    patches, setup_mocks = _patch_risk_assess_pipeline(gate_passed=False, authorization_decision="DATO")

    mocks: dict[str, MagicMock] = {}
    with_contexts = []
    for name, p in patches.items():
        cm = p
        mock = cm.__enter__()
        mocks[name] = mock
        with_contexts.append(cm)

    try:
        setup_mocks(mocks)

        runner = CliRunner()
        result = runner.invoke(cli, [
            "risk-assess", "/fake/path",
            "--product", "payment-api",
            "--output", str(output_dir),
        ])

        assert result.exit_code == 0
        assert "POA&M" in result.output or "POA" in result.output

        # Check POA&M report content
        poam_data = yaml.safe_load((output_dir / "poam-payment-api.yaml").read_text())
        assert "items" in poam_data
        assert len(poam_data["items"]) > 0
        assert poam_data["items"][0]["id"] == "POAM-2026-0503-001"
    finally:
        for cm in with_contexts:
            cm.__exit__(None, None, None)


def test_risk_assess_json_format(tmp_path: Path) -> None:
    """risk-assess --format json should produce JSON reports."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    patches, setup_mocks = _patch_risk_assess_pipeline(gate_passed=True, authorization_decision="ATO")

    mocks: dict[str, MagicMock] = {}
    with_contexts = []
    for name, p in patches.items():
        cm = p
        mock = cm.__enter__()
        mocks[name] = mock
        with_contexts.append(cm)

    try:
        setup_mocks(mocks)

        runner = CliRunner()
        result = runner.invoke(cli, [
            "risk-assess", "/fake/path",
            "--product", "payment-api",
            "--output", str(output_dir),
            "--format", "json",
        ])

        assert result.exit_code == 0

        # Check JSON files exist and are parseable
        for fname in [
            "sp800-30-payment-api.json",
            "sar-payment-api.json",
            "poam-payment-api.json",
            "authorization-payment-api.json",
        ]:
            fpath = output_dir / fname
            assert fpath.exists(), f"Missing report: {fname}"
            data = json.loads(fpath.read_text())
            assert data is not None
    finally:
        for cm in with_contexts:
            cm.__exit__(None, None, None)
