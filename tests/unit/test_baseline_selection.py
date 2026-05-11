"""Tests for baseline selection logic."""

from __future__ import annotations

import os

import pytest

from orchestrator.controls.baseline import select_baseline
from orchestrator.controls.repository import ControlsRepository
from orchestrator.types import ProductManifest, RiskTier

BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def repo() -> ControlsRepository:
    r = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
    r.load_all()
    return r


class TestSelectBaseline:
    def test_payment_api_high_tier(self, repo: ControlsRepository, sample_manifest: ProductManifest) -> None:
        controls = select_baseline(repo, sample_manifest, RiskTier.HIGH)
        control_ids = {c.id for c in controls}
        # PCI + ASVS controls should be selected for HIGH tier
        assert any(cid.startswith("PCI-DSS") for cid in control_ids)
        assert any(cid.startswith("ASVS") for cid in control_ids)
        # All returned controls should apply to HIGH tier
        for c in controls:
            assert RiskTier.HIGH in c.applicable_tiers

    def test_non_pci_manifest_excludes_pci(self, repo: ControlsRepository) -> None:
        manifest = ProductManifest(
            name="internal-tool",
            description="Internal dashboard",
            data_classification=["internal"],
            jurisdiction=["US"],
            deployment={"cloud": "AWS", "compute": "EC2", "region": "us-east-1"},
            integrations=[],
        )
        # MEDIUM tier → only ASVS frameworks per tier-mappings
        controls = select_baseline(repo, manifest, RiskTier.MEDIUM)
        control_ids = {c.id for c in controls}
        assert not any(cid.startswith("PCI-DSS") for cid in control_ids)
