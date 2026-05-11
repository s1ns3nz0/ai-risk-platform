"""Baseline selection — deterministic, no AI involvement (ADR-004)."""

from __future__ import annotations

from orchestrator.controls.models import Control
from orchestrator.controls.repository import ControlsRepository
from orchestrator.types import ProductManifest, RiskTier


def select_baseline(
    repo: ControlsRepository,
    manifest: ProductManifest,
    tier: RiskTier,
) -> list[Control]:
    """
    tier-mappings.yaml + product manifest를 기반으로 적용 컨트롤 목록을 반환.
    이 함수는 deterministic — AI가 관여하지 않는다.
    """
    # Get controls applicable to this tier
    tier_controls = repo.get_baseline_for_tier(tier)

    # Filter by product context (data classification, jurisdiction)
    product_controls = repo.get_controls_for_product(manifest)
    product_control_ids = {c.id for c in product_controls}

    return [c for c in tier_controls if c.id in product_control_ids]
