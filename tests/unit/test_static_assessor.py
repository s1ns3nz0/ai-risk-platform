"""Tests for StaticRiskAssessor — deterministic risk assessment without AI."""

from __future__ import annotations

import re

from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.types import Finding, ProductManifest, RiskReport, RiskTier


def _make_manifest(
    data_classification: list[str] | None = None,
    jurisdiction: list[str] | None = None,
) -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="test",
        data_classification=data_classification or [],
        jurisdiction=jurisdiction or [],
        deployment={"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        integrations=[],
    )


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


def _make_control(control_id: str = "PCI-DSS-6.3.1") -> Control:
    return Control(
        id=control_id,
        title="Test Control",
        framework="pci-dss-4.0",
        description="Test",
        verification_methods=[
            VerificationMethod(scanner="semgrep", rules=["test-rule"]),
        ],
        applicable_tiers=[RiskTier.HIGH, RiskTier.CRITICAL],
    )


class TestCategorizePci:
    def test_categorize_pci(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["PCI"])
        tier = assessor.categorize(manifest)
        assert tier == RiskTier.HIGH


class TestCategorizePciJp:
    def test_categorize_pci_jp(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["PCI"], jurisdiction=["JP"])
        tier = assessor.categorize(manifest)
        assert tier == RiskTier.CRITICAL


class TestCategorizePii:
    def test_categorize_pii(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["PII-financial"])
        tier = assessor.categorize(manifest)
        assert tier == RiskTier.MEDIUM


class TestCategorizePublic:
    def test_categorize_public(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["public"])
        tier = assessor.categorize(manifest)
        assert tier == RiskTier.LOW


class TestAssessProducesRiskReport:
    def test_assess_produces_risk_report(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["PCI"])
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        report = assessor.assess(findings, manifest, controls, "pre-merge")
        assert isinstance(report, RiskReport)
        assert report.product == "payment-api"
        assert report.trigger == "pre-merge"
        assert report.risk_score >= 0.0
        assert report.risk_score <= 10.0


class TestAssessNarrativeIsNotEmpty:
    def test_assess_narrative_is_not_empty(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["PCI"])
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        report = assessor.assess(findings, manifest, controls, "pre-merge")
        assert report.narrative != ""
        assert len(report.narrative) > 10


class TestAssessReportIdFormat:
    def test_assess_report_id_format(self) -> None:
        assessor = StaticRiskAssessor()
        manifest = _make_manifest(data_classification=["PCI"])
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        report = assessor.assess(findings, manifest, controls, "pre-merge")
        # RA-YYYY-MMDD-NNN
        assert re.match(r"^RA-\d{4}-\d{4}-\d{3}$", report.id)
