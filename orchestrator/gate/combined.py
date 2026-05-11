"""Combined gate evaluator — two additive layers.

YAML thresholds (fast path) + OPA/Rego (detailed path).
Both must pass. Gate path is 100% local (ADR-003, ADR-004).
"""

from __future__ import annotations

import logging

from orchestrator.gate.opa import OpaEvaluator
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.types import Finding, GateDecision, RiskTier

logger = logging.getLogger(__name__)


class CombinedGateEvaluator:
    """Two additive gate layers: YAML thresholds + OPA/Rego.

    Both must pass. YAML is evaluated first (fast path).
    If YAML fails, OPA is skipped (already blocked).
    If YAML passes, OPA evaluates (detailed path).

    Rules:
    - Both layers must pass for gate to PASS
    - Deny messages from failing layer included in reason
    - OPA not installed or no rego files → YAML only
    """

    def __init__(
        self,
        threshold_evaluator: ThresholdEvaluator,
        opa_evaluator: OpaEvaluator | None = None,
    ) -> None:
        self._threshold = threshold_evaluator
        self._opa = opa_evaluator

    def evaluate(
        self,
        findings: list[Finding],
        tier: RiskTier,
        context: dict[str, object] | None = None,
    ) -> GateDecision:
        """Evaluate findings through both gate layers."""
        # Layer 1: YAML thresholds (fast path)
        yaml_result = self._threshold.evaluate(findings, tier)

        if not yaml_result.passed:
            return GateDecision(
                passed=False,
                reason=f"YAML thresholds: {yaml_result.reason}",
                threshold_results=yaml_result.threshold_results,
                findings_count=yaml_result.findings_count,
            )

        # Layer 2: OPA/Rego (detailed path) — only if OPA is configured
        if self._opa is None:
            return GateDecision(
                passed=True,
                reason="YAML thresholds: passed; OPA/Rego: skipped (not configured)",
                threshold_results=yaml_result.threshold_results,
                findings_count=yaml_result.findings_count,
            )

        opa_result = self._opa.evaluate(findings, context or {})

        if not opa_result.passed:
            return GateDecision(
                passed=False,
                reason=f"OPA/Rego: {opa_result.reason}",
                threshold_results=yaml_result.threshold_results,
                findings_count=yaml_result.findings_count,
            )

        return GateDecision(
            passed=True,
            reason=f"YAML thresholds: passed; OPA/Rego: {opa_result.reason}",
            threshold_results=yaml_result.threshold_results,
            findings_count=yaml_result.findings_count,
        )
