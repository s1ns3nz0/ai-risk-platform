"""RiskAssessor Protocol — Strategy pattern interface (ADR-004)."""

from __future__ import annotations

from typing import Protocol

from orchestrator.controls.models import Control
from orchestrator.types import Finding, ProductManifest, RiskReport, RiskTier


class RiskAssessor(Protocol):
    """Strategy pattern 인터페이스.

    StaticRiskAssessor와 BedrockRiskAssessor가 동일한 인터페이스를 구현한다.
    """

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """제품을 카테고리화하여 risk tier를 반환 (RMF Step 2)."""
        ...

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> RiskReport:
        """findings를 평가하여 risk report를 생성 (RMF Step 5)."""
        ...
