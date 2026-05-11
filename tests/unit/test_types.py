"""Tests for core data types."""

from __future__ import annotations

from orchestrator.types import (
    Finding,
    GateDecision,
    ProductManifest,
    RiskProfile,
    RiskReport,
    RiskTier,
)


class TestRiskTier:
    def test_enum_values(self) -> None:
        assert RiskTier.LOW.value == "low"
        assert RiskTier.MEDIUM.value == "medium"
        assert RiskTier.HIGH.value == "high"
        assert RiskTier.CRITICAL.value == "critical"

    def test_enum_from_value(self) -> None:
        assert RiskTier("high") is RiskTier.HIGH


class TestProductManifest:
    def test_creation(self, sample_manifest: ProductManifest) -> None:
        assert sample_manifest.name == "payment-api"
        assert sample_manifest.data_classification == ["PCI", "PII-financial"]
        assert sample_manifest.jurisdiction == ["JP"]
        assert sample_manifest.deployment["cloud"] == "AWS"

    def test_integrations_default(self) -> None:
        m = ProductManifest(
            name="test",
            description="test",
            data_classification=[],
            jurisdiction=[],
            deployment={},
        )
        assert m.integrations == []


class TestRiskProfile:
    def test_creation(self, sample_profile: RiskProfile) -> None:
        assert sample_profile.risk_appetite == "conservative"
        assert "pci-dss-4.0" in sample_profile.frameworks
        assert sample_profile.thresholds["critical"]["action"] == "block"

    def test_failure_policy(self, sample_profile: RiskProfile) -> None:
        assert sample_profile.failure_policy["critical"]["scan_failure"] == "block"
        assert sample_profile.failure_policy["low"]["scan_failure"] == "proceed"


class TestFinding:
    def test_creation(self, sample_finding: Finding) -> None:
        assert sample_finding.source == "semgrep"
        assert sample_finding.severity == "high"
        assert "PCI-DSS-6.3.1" in sample_finding.control_ids
        assert sample_finding.product == "payment-api"

    def test_empty_control_ids(self) -> None:
        f = Finding(
            source="grype",
            rule_id="CVE-2023-0001",
            severity="low",
            file="requirements.txt",
            line=1,
            message="test",
            control_ids=[],
            product="payment-api",
        )
        assert f.control_ids == []


class TestRiskReport:
    def test_creation(self) -> None:
        report = RiskReport(
            id="RA-2026-0419-001",
            trigger="pre_merge",
            product="payment-api",
            risk_tier=RiskTier.HIGH,
            likelihood="high",
            impact="high",
            risk_score=8.5,
            narrative="Critical findings detected.",
            findings_summary={"critical": 1, "high": 2},
            affected_controls=["PCI-DSS-6.3.1"],
            gate_recommendation="block",
        )
        assert report.risk_tier is RiskTier.HIGH
        assert report.risk_score == 8.5
        assert report.gate_recommendation == "block"


class TestGateDecision:
    def test_creation(self) -> None:
        gate = GateDecision(
            passed=False,
            reason="critical findings exceed threshold",
            threshold_results=[{"name": "max_critical_findings", "limit": 0, "actual": 1, "passed": False}],
            findings_count={"critical": 1, "high": 2, "medium": 0, "low": 0},
        )
        assert not gate.passed
        assert gate.findings_count["critical"] == 1

    def test_passing_gate(self) -> None:
        gate = GateDecision(
            passed=True,
            reason="all checks passed",
            threshold_results=[{"name": "max_critical_findings", "limit": 0, "actual": 0, "passed": True}],
            findings_count={"critical": 0, "high": 0, "medium": 1, "low": 3},
        )
        assert gate.passed
        assert gate.reason == "all checks passed"
