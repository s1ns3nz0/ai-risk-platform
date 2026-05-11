"""Tests for BedrockRiskAssessor — AI-powered risk assessment with fallback."""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock

from orchestrator.assessor.bedrock import BedrockRiskAssessor
from orchestrator.assessor.bedrock_client import BedrockClient, BedrockInvocationError
from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.types import Finding, ProductManifest, RiskReport, RiskTier


def _make_manifest(
    data_classification: list[str] | None = None,
    jurisdiction: list[str] | None = None,
) -> ProductManifest:
    return ProductManifest(
        name="payment-api",
        description="QR code payment confirmation service",
        data_classification=data_classification or ["PCI", "PII-financial"],
        jurisdiction=jurisdiction or ["JP"],
        deployment={"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        integrations=["external-payment-gateway"],
    )


def _make_finding(
    severity: str = "high",
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
        control_ids=control_ids or ["PCI-DSS-6.3.1"],
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


def _mock_client(response: str) -> BedrockClient:
    client = MagicMock(spec=BedrockClient)
    client.invoke.return_value = response
    return client


def _failing_client() -> BedrockClient:
    client = MagicMock(spec=BedrockClient)
    client.invoke.side_effect = BedrockInvocationError("Bedrock unavailable")
    return client


class TestCategorizeAiResponse:
    def test_categorize_parses_ai_response(self) -> None:
        response = json.dumps({
            "tier": "critical",
            "reasoning": "PCI cardholder data in JP jurisdiction under FISC regulation.",
            "threat_profile": ["T1190", "T1078"],
        })
        client = _mock_client(response)
        assessor = BedrockRiskAssessor(client=client)

        manifest = _make_manifest()
        tier = assessor.categorize(manifest)

        assert tier == RiskTier.CRITICAL
        client.invoke.assert_called_once()


class TestCategorizeFallbackOnFailure:
    def test_categorize_fallback_on_failure(self) -> None:
        client = _failing_client()
        fallback = StaticRiskAssessor()
        assessor = BedrockRiskAssessor(client=client, fallback=fallback)

        manifest = _make_manifest(data_classification=["PCI"], jurisdiction=["JP"])
        tier = assessor.categorize(manifest)

        assert tier == RiskTier.CRITICAL  # StaticRiskAssessor result


class TestCategorizeFallbackOnInvalidJson:
    def test_categorize_fallback_on_invalid_json(self) -> None:
        client = _mock_client("This is not valid JSON at all")
        fallback = StaticRiskAssessor()
        assessor = BedrockRiskAssessor(client=client, fallback=fallback)

        manifest = _make_manifest(data_classification=["PCI"], jurisdiction=["US"])
        tier = assessor.categorize(manifest)

        assert tier == RiskTier.HIGH  # StaticRiskAssessor: PCI without JP → HIGH


class TestAssessCombinesScoreAndNarrative:
    def test_assess_combines_score_and_narrative(self) -> None:
        ai_response = json.dumps({
            "narrative": "Cross-signal analysis reveals a critical SQL injection finding.",
            "cross_signal_insights": ["SQLi + exposed secret = credential theft chain"],
            "recommendations": ["Fix SQL injection in export.py line 42"],
            "gate_recommendation": "block",
        })
        client = _mock_client(ai_response)
        assessor = BedrockRiskAssessor(client=client)

        manifest = _make_manifest()
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        report = assessor.assess(findings, manifest, controls, "pre-merge")

        assert isinstance(report, RiskReport)
        assert "Cross-signal analysis" in report.narrative
        assert report.risk_score >= 0.0
        assert report.risk_score <= 10.0
        assert report.product == "payment-api"
        assert re.match(r"^RA-\d{4}-\d{4}-\d{3}$", report.id)


class TestAssessFallbackOnFailure:
    def test_assess_fallback_on_failure(self) -> None:
        client = _failing_client()
        fallback = StaticRiskAssessor()
        assessor = BedrockRiskAssessor(client=client, fallback=fallback)

        manifest = _make_manifest()
        controls = [_make_control()]
        findings = [_make_finding(severity="high")]

        report = assessor.assess(findings, manifest, controls, "pre-merge")

        assert isinstance(report, RiskReport)
        assert report.risk_score >= 0.0
        assert report.narrative != ""


class TestAssessUsesDeterministicScore:
    def test_assess_uses_deterministic_score(self) -> None:
        """AI가 다른 score를 제안해도 compute_risk_score의 결과를 사용."""
        ai_response = json.dumps({
            "narrative": "AI suggests score of 9.5 but deterministic score should prevail.",
            "cross_signal_insights": [],
            "recommendations": [],
            "gate_recommendation": "block",
            "risk_score": 9.5,  # AI tries to override — should be ignored
        })
        client = _mock_client(ai_response)
        assessor = BedrockRiskAssessor(client=client)

        manifest = _make_manifest(data_classification=["PUBLIC"], jurisdiction=["US"])
        controls = [_make_control()]
        findings = [_make_finding(severity="low")]

        report = assessor.assess(findings, manifest, controls, "pre-merge")

        # Score should be low for PUBLIC data with low severity finding
        # NOT the 9.5 that AI suggested
        assert report.risk_score < 5.0
