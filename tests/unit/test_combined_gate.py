"""Tests for CombinedGateEvaluator — two additive gate layers."""

from __future__ import annotations

from unittest.mock import MagicMock

from orchestrator.gate.combined import CombinedGateEvaluator
from orchestrator.gate.opa import OpaEvaluator
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.types import Finding, GateDecision, RiskTier


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


def _gate(passed: bool, reason: str) -> GateDecision:
    return GateDecision(passed=passed, reason=reason, threshold_results=[], findings_count={})


class TestBothPass:
    def test_both_pass(self) -> None:
        threshold = MagicMock(spec=ThresholdEvaluator)
        threshold.evaluate.return_value = _gate(True, "all checks passed")

        opa = MagicMock(spec=OpaEvaluator)
        opa.evaluate.return_value = _gate(True, "opa: all policies passed")

        combined = CombinedGateEvaluator(threshold, opa)
        findings = [_make_finding()]
        result = combined.evaluate(findings, RiskTier.CRITICAL, {"tier": "critical"})

        assert result.passed
        threshold.evaluate.assert_called_once_with(findings, RiskTier.CRITICAL)
        opa.evaluate.assert_called_once()


class TestYamlFailsOpaSkipped:
    def test_yaml_fails_opa_skipped(self) -> None:
        threshold = MagicMock(spec=ThresholdEvaluator)
        threshold.evaluate.return_value = _gate(False, "BLOCKED: max_critical_findings violated")

        opa = MagicMock(spec=OpaEvaluator)

        combined = CombinedGateEvaluator(threshold, opa)
        findings = [_make_finding(severity="critical")]
        result = combined.evaluate(findings, RiskTier.CRITICAL, {"tier": "critical"})

        assert not result.passed
        assert "max_critical_findings" in result.reason
        opa.evaluate.assert_not_called()


class TestYamlPassesOpaFails:
    def test_yaml_passes_opa_fails(self) -> None:
        threshold = MagicMock(spec=ThresholdEvaluator)
        threshold.evaluate.return_value = _gate(True, "all checks passed")

        opa = MagicMock(spec=OpaEvaluator)
        opa.evaluate.return_value = _gate(
            False, "Critical finding in PCI scope: CKV_AWS_24"
        )

        combined = CombinedGateEvaluator(threshold, opa)
        findings = [_make_finding()]
        result = combined.evaluate(findings, RiskTier.CRITICAL, {"tier": "critical"})

        assert not result.passed
        assert "CKV_AWS_24" in result.reason


class TestOpaNoneYamlOnly:
    def test_opa_none_yaml_only(self) -> None:
        threshold = MagicMock(spec=ThresholdEvaluator)
        threshold.evaluate.return_value = _gate(True, "all checks passed")

        combined = CombinedGateEvaluator(threshold, None)
        findings = [_make_finding()]
        result = combined.evaluate(findings, RiskTier.MEDIUM)

        assert result.passed
        threshold.evaluate.assert_called_once()


class TestCombinedReasonIncludesBoth:
    def test_combined_reason_includes_both(self) -> None:
        """When YAML fails, OPA is skipped — so 'both' means YAML reason only.

        This test verifies the reason from the failing layer is preserved.
        """
        threshold = MagicMock(spec=ThresholdEvaluator)
        threshold.evaluate.return_value = _gate(
            False, "BLOCKED: max_critical_findings violated"
        )

        opa = MagicMock(spec=OpaEvaluator)

        combined = CombinedGateEvaluator(threshold, opa)
        findings = [_make_finding(severity="critical")]
        result = combined.evaluate(findings, RiskTier.CRITICAL, {"tier": "critical"})

        assert "BLOCKED" in result.reason
        assert "YAML thresholds" in result.reason
