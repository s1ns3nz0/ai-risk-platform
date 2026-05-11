"""FailureHandler — tier-based scanner failure policy."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from orchestrator.resilience.retry import RetryResult
from orchestrator.types import RiskProfile, RiskTier

logger = logging.getLogger(__name__)


@dataclass
class FailureDecision:
    """Failure handler의 결정."""

    action: str  # "block" | "warn_and_proceed" | "proceed"
    reason: str
    failed_scanners: list[str] = field(default_factory=list)
    tier: str = ""
    override_available: bool = False


class FailureHandler:
    """Scanner failure에 대한 tier별 정책 처리.

    Red Team RT-23에서 결정된 정책:
    - Critical/High: fail-closed (block). Override 가능.
    - Medium/Low: warn_and_proceed. Override 불필요.

    핵심 규칙:
    - Gate path에 영향. Scanner 실패 시 gate가 block할 수 있음.
    - 하지만 AI가 결정하는 것이 아님 — failure_policy가 결정 (deterministic).
    """

    def __init__(self, profile: RiskProfile) -> None:
        self._failure_policy = profile.failure_policy

    def handle(self, retry_results: list[RetryResult], tier: RiskTier) -> FailureDecision:
        """실패한 scanner에 대해 tier별 failure_policy 적용.

        1. retry_results에서 실패한 scanner 추출
        2. risk-profile.yaml의 failure_policy[tier] 조회
        3. scan_failure: "block" → FailureDecision(action="block")
        4. scan_failure: "proceed" → FailureDecision(action="warn_and_proceed")
        5. 모든 scanner 성공 → FailureDecision(action="proceed", no failures)
        """
        failed = [r.scanner for r in retry_results if not r.success]
        tier_value = tier.value

        if not failed:
            return FailureDecision(
                action="proceed",
                reason="All scanners succeeded",
                failed_scanners=[],
                tier=tier_value,
                override_available=False,
            )

        policy = self._failure_policy.get(tier_value, {})
        scan_failure_action = policy.get("scan_failure", "proceed")

        if scan_failure_action == "block":
            logger.warning(
                "Tier %s failure policy: BLOCK — failed scanners: %s",
                tier_value,
                ", ".join(failed),
            )
            return FailureDecision(
                action="block",
                reason=f"Tier {tier_value} failure policy: block on scan failure ({', '.join(failed)})",
                failed_scanners=failed,
                tier=tier_value,
                override_available=True,
            )

        logger.info(
            "Tier %s failure policy: warn_and_proceed — failed scanners: %s",
            tier_value,
            ", ".join(failed),
        )
        return FailureDecision(
            action="warn_and_proceed",
            reason=f"Tier {tier_value} failure policy: warn and proceed ({', '.join(failed)})",
            failed_scanners=failed,
            tier=tier_value,
            override_available=False,
        )
