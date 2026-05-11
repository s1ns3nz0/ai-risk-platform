"""Tests for FailureHandler — tier-based failure policy."""

from __future__ import annotations

from orchestrator.resilience.failure import FailureHandler
from orchestrator.resilience.retry import RetryResult
from orchestrator.types import RiskProfile, RiskTier


def _profile() -> RiskProfile:
    """Minimal risk profile with failure_policy."""
    return RiskProfile(
        frameworks=["pci-dss-4.0"],
        risk_appetite="conservative",
        thresholds={},
        failure_policy={
            "critical": {"scan_failure": "block"},
            "high": {"scan_failure": "block"},
            "medium": {"scan_failure": "proceed"},
            "low": {"scan_failure": "proceed"},
        },
    )


def _success(name: str) -> RetryResult:
    return RetryResult(scanner=name, success=True, attempts=1, total_time=0.5, error_message="")


def _failure(name: str) -> RetryResult:
    return RetryResult(scanner=name, success=False, attempts=3, total_time=95.0, error_message="timeout")


class TestFailureHandler:
    def test_no_failures_proceeds(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_success("checkov"), _success("semgrep")],
            RiskTier.CRITICAL,
        )
        assert decision.action == "proceed"
        assert decision.failed_scanners == []

    def test_critical_tier_blocks_on_failure(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_success("checkov"), _failure("semgrep")],
            RiskTier.CRITICAL,
        )
        assert decision.action == "block"
        assert "semgrep" in decision.failed_scanners

    def test_high_tier_blocks_on_failure(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_failure("grype")],
            RiskTier.HIGH,
        )
        assert decision.action == "block"
        assert "grype" in decision.failed_scanners

    def test_medium_tier_warns_on_failure(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_failure("checkov"), _success("semgrep")],
            RiskTier.MEDIUM,
        )
        assert decision.action == "warn_and_proceed"
        assert "checkov" in decision.failed_scanners

    def test_low_tier_warns_on_failure(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_failure("gitleaks")],
            RiskTier.LOW,
        )
        assert decision.action == "warn_and_proceed"

    def test_override_available_for_critical(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_failure("semgrep")],
            RiskTier.CRITICAL,
        )
        assert decision.override_available is True

    def test_override_not_available_for_medium(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_failure("semgrep")],
            RiskTier.MEDIUM,
        )
        assert decision.override_available is False

    def test_failure_decision_lists_failed_scanners(self) -> None:
        handler = FailureHandler(_profile())
        decision = handler.handle(
            [_failure("checkov"), _success("semgrep"), _failure("grype")],
            RiskTier.HIGH,
        )
        assert sorted(decision.failed_scanners) == ["checkov", "grype"]
        assert decision.tier == "high"
