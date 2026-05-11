"""Tests for ControlsRepository."""

from __future__ import annotations

import os

import pytest

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.controls.repository import ControlsRepository
from orchestrator.types import RiskTier

BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def repo() -> ControlsRepository:
    r = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
    r.load_all()
    return r


class TestLoadAll:
    def test_loads_102_controls(self, repo: ControlsRepository) -> None:
        assert len(repo.controls) == 102

    def test_controls_are_control_instances(self, repo: ControlsRepository) -> None:
        for control in repo.controls.values():
            assert isinstance(control, Control)

    def test_each_control_has_verification_methods(self, repo: ControlsRepository) -> None:
        for control in repo.controls.values():
            assert len(control.verification_methods) > 0
            for vm in control.verification_methods:
                assert isinstance(vm, VerificationMethod)


class TestGetControl:
    def test_existing_control(self, repo: ControlsRepository) -> None:
        ctrl = repo.get_control("PCI-DSS-6.3.1")
        assert ctrl.id == "PCI-DSS-6.3.1"
        assert ctrl.framework == "pci-dss-4.0"
        assert ctrl.title != ""

    def test_nonexistent_control(self, repo: ControlsRepository) -> None:
        with pytest.raises(KeyError):
            repo.get_control("NONEXISTENT")


class TestGetBaselineForTier:
    def test_high_tier_selects_pci_and_asvs(self, repo: ControlsRepository) -> None:
        controls = repo.get_baseline_for_tier(RiskTier.HIGH)
        frameworks = {c.framework for c in controls}
        assert "pci-dss-4.0" in frameworks
        assert "asvs-4.0.3-L3" in frameworks
        assert "fisc-safety" not in frameworks

    def test_low_tier_returns_empty(self, repo: ControlsRepository) -> None:
        controls = repo.get_baseline_for_tier(RiskTier.LOW)
        assert controls == []

    def test_critical_tier_selects_all_three(self, repo: ControlsRepository) -> None:
        controls = repo.get_baseline_for_tier(RiskTier.CRITICAL)
        frameworks = {c.framework for c in controls}
        assert "pci-dss-4.0" in frameworks
        assert "asvs-4.0.3-L3" in frameworks
        assert "fisc-safety" in frameworks

    def test_medium_tier_selects_asvs_only(self, repo: ControlsRepository) -> None:
        controls = repo.get_baseline_for_tier(RiskTier.MEDIUM)
        frameworks = {c.framework for c in controls}
        assert "asvs-4.0.3-L3" in frameworks
        assert "pci-dss-4.0" not in frameworks


class TestGetVerificationMethods:
    def test_semgrep_methods_for_pci_6_3_1(self, repo: ControlsRepository) -> None:
        methods = repo.get_verification_methods("PCI-DSS-6.3.1", "semgrep")
        assert len(methods) == 1
        assert methods[0]["scanner"] == "semgrep"
        assert "rules" in methods[0]

    def test_no_methods_for_wrong_scanner(self, repo: ControlsRepository) -> None:
        methods = repo.get_verification_methods("PCI-DSS-10.2.1", "grype")
        assert methods == []

    def test_nonexistent_control_raises(self, repo: ControlsRepository) -> None:
        with pytest.raises(KeyError):
            repo.get_verification_methods("NONEXISTENT", "semgrep")
