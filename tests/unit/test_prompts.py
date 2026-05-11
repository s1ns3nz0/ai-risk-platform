"""Tests for Bedrock prompt templates."""

from __future__ import annotations

from orchestrator.assessor.prompts import (
    build_assessment_prompt,
    build_categorization_prompt,
)
from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.types import Finding, ProductManifest, RiskTier


def _make_manifest() -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="QR code payment confirmation service",
        data_classification=["PCI", "PII-financial"],
        jurisdiction=["JP"],
        deployment={"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        integrations=["external-payment-gateway"],
    )


def _make_finding(severity: str = "high", source: str = "semgrep") -> Finding:
    return Finding(
        source=source,
        rule_id="test-rule",
        severity=severity,
        file="test.py",
        line=1,
        message="test finding",
        control_ids=["PCI-DSS-6.3.1"],
        product="payment-api",
    )


def _make_control(control_id: str = "PCI-DSS-6.3.1") -> Control:
    return Control(
        id=control_id,
        title="Secure Coding",
        framework="pci-dss-4.0",
        description="Ensure secure coding practices",
        verification_methods=[
            VerificationMethod(scanner="semgrep", rules=["test-rule"]),
        ],
        applicable_tiers=[RiskTier.HIGH, RiskTier.CRITICAL],
    )


class TestCategorizationPromptIncludesManifest:
    def test_categorization_prompt_includes_manifest(self) -> None:
        manifest = _make_manifest()
        prompt = build_categorization_prompt(manifest)
        assert "payment-api" in prompt
        assert "QR code payment confirmation service" in prompt
        assert "PCI" in prompt
        assert "JP" in prompt


class TestAssessmentPromptIncludesFindingsSummary:
    def test_assessment_prompt_includes_findings_summary(self) -> None:
        manifest = _make_manifest()
        findings = [_make_finding("high"), _make_finding("critical", "gitleaks")]
        controls = [_make_control()]
        prompt = build_assessment_prompt(
            manifest=manifest,
            findings=findings,
            controls=controls,
            risk_tier=RiskTier.CRITICAL,
            risk_score=7.5,
            trigger="pre-merge",
        )
        assert "2 total" in prompt or "2" in prompt
        assert "semgrep" in prompt or "gitleaks" in prompt


class TestAssessmentPromptIncludesRiskScore:
    def test_assessment_prompt_includes_risk_score(self) -> None:
        manifest = _make_manifest()
        findings = [_make_finding()]
        controls = [_make_control()]
        prompt = build_assessment_prompt(
            manifest=manifest,
            findings=findings,
            controls=controls,
            risk_tier=RiskTier.HIGH,
            risk_score=6.2,
            trigger="pre-merge",
        )
        assert "6.2" in prompt
