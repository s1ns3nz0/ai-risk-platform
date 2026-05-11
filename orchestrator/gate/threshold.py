"""YAML threshold-based gate evaluator.

Deterministic gate engine — no AI, no network calls.
Gate path is 100% local (ADR-003, ADR-004).
"""

from __future__ import annotations

from collections import Counter

from orchestrator.types import Finding, GateDecision, RiskProfile, RiskTier


class ThresholdEvaluator:
    """Evaluate findings against risk-profile.yaml thresholds.

    All thresholds are AND conditions — any single violation fails the gate.
    """

    def __init__(self, profile: RiskProfile) -> None:
        self._thresholds = profile.thresholds

    def evaluate(self, findings: list[Finding], tier: RiskTier) -> GateDecision:
        """Evaluate findings against the tier's thresholds."""
        tier_config = self._thresholds.get(tier.value, {})
        action = tier_config.get("action", "proceed")

        severity_counts = Counter(f.severity for f in findings)
        findings_count = {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        }

        if action == "proceed":
            return GateDecision(
                passed=True,
                reason="all checks passed",
                threshold_results=[],
                findings_count=findings_count,
            )

        secrets_count = sum(1 for f in findings if f.source == "gitleaks")
        pci_high_count = sum(
            1
            for f in findings
            if f.severity == "high" and any(cid.startswith("PCI-DSS-") for cid in f.control_ids)
        )

        def _get_limit(key: str) -> int | None:
            val = tier_config.get(key)
            if val is None:
                return None
            assert isinstance(val, int)
            return val

        evaluators: list[tuple[str, int, int | None]] = [
            ("max_critical_findings", findings_count["critical"], _get_limit("max_critical_findings")),
            ("max_secrets_detected", secrets_count, _get_limit("max_secrets_detected")),
            ("max_high_findings_pci", pci_high_count, _get_limit("max_high_findings_pci")),
            ("max_high_findings", findings_count["high"], _get_limit("max_high_findings")),
        ]

        threshold_results: list[dict[str, object]] = []
        violations: list[str] = []

        for name, actual, limit in evaluators:
            if limit is None:
                continue
            passed = actual <= limit
            threshold_results.append(
                {"name": name, "limit": limit, "actual": actual, "passed": passed}
            )
            if not passed:
                control_ref = self._find_violation_control(name, findings)
                violations.append(
                    f"BLOCKED: {name} violated — found {actual}, limit {limit}"
                    + (f" (control: {control_ref})" if control_ref else "")
                )

        if violations:
            return GateDecision(
                passed=False,
                reason="; ".join(violations),
                threshold_results=threshold_results,
                findings_count=findings_count,
            )

        return GateDecision(
            passed=True,
            reason="all checks passed",
            threshold_results=threshold_results,
            findings_count=findings_count,
        )

    @staticmethod
    def _find_violation_control(threshold_name: str, findings: list[Finding]) -> str:
        """Find the first relevant control ID for a threshold violation."""
        if threshold_name == "max_critical_findings":
            for f in findings:
                if f.severity == "critical" and f.control_ids:
                    return f.control_ids[0]
        elif threshold_name == "max_secrets_detected":
            for f in findings:
                if f.source == "gitleaks" and f.control_ids:
                    return f.control_ids[0]
        elif threshold_name == "max_high_findings_pci":
            for f in findings:
                if f.severity == "high":
                    for cid in f.control_ids:
                        if cid.startswith("PCI-DSS-"):
                            return cid
        elif threshold_name == "max_high_findings":
            for f in findings:
                if f.severity == "high" and f.control_ids:
                    return f.control_ids[0]
        return ""
