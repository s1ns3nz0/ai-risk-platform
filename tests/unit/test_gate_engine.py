"""Tests for ThresholdEvaluator — gate engine."""

from __future__ import annotations

import os

import pytest

from orchestrator.config.profile import load_profile
from orchestrator.controls.repository import ControlsRepository
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.scanners.checkov import CheckovScanner
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.gitleaks import GitleaksScanner
from orchestrator.scanners.grype import GrypeScanner
from orchestrator.scanners.semgrep import SemgrepScanner
from orchestrator.types import Finding, GateDecision, RiskProfile, RiskTier

PROFILE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "controls", "products", "payment-api", "risk-profile.yaml"
)
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "scanner-outputs")
BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def profile() -> RiskProfile:
    return load_profile(PROFILE_PATH)


@pytest.fixture
def evaluator(profile: RiskProfile) -> ThresholdEvaluator:
    return ThresholdEvaluator(profile)


def _make_finding(
    severity: str = "medium",
    source: str = "semgrep",
    control_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        source=source,
        rule_id="test-rule",
        severity=severity,
        file="test.py",
        line=1,
        message="test finding",
        control_ids=control_ids or [],
        product="payment-api",
    )


class TestCleanFindingsPassGate:
    def test_clean_findings_pass_gate(self, evaluator: ThresholdEvaluator) -> None:
        decision = evaluator.evaluate([], RiskTier.CRITICAL)
        assert decision.passed
        assert isinstance(decision, GateDecision)


class TestCriticalFindingBlocks:
    def test_critical_finding_blocks(self, evaluator: ThresholdEvaluator) -> None:
        findings = [_make_finding(severity="critical")]
        decision = evaluator.evaluate(findings, RiskTier.CRITICAL)
        assert not decision.passed
        assert "max_critical_findings" in decision.reason
        assert "BLOCKED" in decision.reason


class TestSecretFindingBlocks:
    def test_secret_finding_blocks(self, evaluator: ThresholdEvaluator) -> None:
        findings = [_make_finding(source="gitleaks", severity="critical")]
        decision = evaluator.evaluate(findings, RiskTier.CRITICAL)
        assert not decision.passed
        assert "max_secrets_detected" in decision.reason or "max_critical_findings" in decision.reason


class TestHighPciFindingBlocks:
    def test_high_pci_finding_blocks(self, evaluator: ThresholdEvaluator) -> None:
        findings = [_make_finding(severity="high", control_ids=["PCI-DSS-6.3.1"])]
        decision = evaluator.evaluate(findings, RiskTier.HIGH)
        assert not decision.passed
        assert "max_high_findings_pci" in decision.reason


class TestMediumFindingsPass:
    def test_medium_findings_pass(self, evaluator: ThresholdEvaluator) -> None:
        findings = [_make_finding(severity="medium") for _ in range(5)]
        decision = evaluator.evaluate(findings, RiskTier.MEDIUM)
        assert decision.passed


class TestLowTierAlwaysPasses:
    def test_low_tier_always_passes(self, evaluator: ThresholdEvaluator) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(source="gitleaks", severity="critical"),
        ]
        decision = evaluator.evaluate(findings, RiskTier.LOW)
        assert decision.passed


class TestGateDecisionContainsThresholdDetails:
    def test_gate_decision_contains_threshold_details(self, evaluator: ThresholdEvaluator) -> None:
        findings = [_make_finding(severity="critical")]
        decision = evaluator.evaluate(findings, RiskTier.CRITICAL)

        assert isinstance(decision.threshold_results, list)
        assert len(decision.threshold_results) > 0
        for result in decision.threshold_results:
            assert "name" in result
            assert "limit" in result
            assert "actual" in result
            assert "passed" in result

        assert isinstance(decision.findings_count, dict)
        assert decision.findings_count["critical"] == 1


class TestGateWithScannerFindings:
    """Integration-style test using scanner fixture outputs."""

    def test_gate_with_scanner_findings(self, evaluator: ThresholdEvaluator) -> None:
        repo = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
        repo.load_all()
        mapper = ControlMapper(repo)

        all_findings: list[Finding] = []

        scanners_and_fixtures = [
            (CheckovScanner(control_mapper=mapper), "checkov_output.json"),
            (SemgrepScanner(control_mapper=mapper), "semgrep_output.json"),
            (GrypeScanner(control_mapper=mapper), "grype_output.json"),
            (GitleaksScanner(control_mapper=mapper), "gitleaks_output.json"),
        ]

        for scanner, fixture_name in scanners_and_fixtures:
            path = os.path.join(FIXTURES_DIR, fixture_name)
            with open(path) as f:
                raw = f.read()
            all_findings.extend(scanner.parse_output(raw))

        decision = evaluator.evaluate(all_findings, RiskTier.CRITICAL)

        # Expect BLOCKED: fixtures contain critical CVE + gitleaks secrets
        assert not decision.passed
        assert "BLOCKED" in decision.reason
        assert decision.findings_count["critical"] >= 1
