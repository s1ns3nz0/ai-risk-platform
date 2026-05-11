"""Tests for ControlMapper — maps scanner rules to Control IDs."""

from __future__ import annotations

import os

import pytest

from orchestrator.controls.repository import ControlsRepository
from orchestrator.scanners.control_mapper import ControlMapper

BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def controls_repo() -> ControlsRepository:
    repo = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
    repo.load_all()
    return repo


@pytest.fixture
def mapper(controls_repo: ControlsRepository) -> ControlMapper:
    return ControlMapper(controls_repo)


class TestMapKnownRule:
    def test_checkov_ckv_aws_19_maps_to_pci_and_fisc(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("checkov", "CKV_AWS_19")
        assert "PCI-DSS-3.5.1" in control_ids
        assert "FISC-実119" in control_ids

    def test_checkov_ckv_aws_24_maps_to_pci(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("checkov", "CKV_AWS_24")
        assert "PCI-DSS-1.3.1" in control_ids

    def test_semgrep_sql_injection_maps_to_pci_and_asvs(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("semgrep", "python.lang.security.injection.sql-injection")
        assert "PCI-DSS-6.3.1" in control_ids
        assert "ASVS-V5.3.4" in control_ids

    def test_semgrep_hardcoded_password_maps(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding(
            "semgrep", "python.lang.security.audit.hardcoded-password.hardcoded-password-default-arg"
        )
        assert "ASVS-V2.10.1" in control_ids

    def test_gitleaks_maps_to_pci_and_asvs(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("gitleaks", "aws-access-key-id")
        assert "PCI-DSS-3.6.1" in control_ids
        assert "ASVS-V2.10.1" in control_ids

    def test_grype_critical_maps_to_pci_and_asvs(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("grype", "CVE-2023-50782", severity="critical")
        assert "PCI-DSS-6.3.1" in control_ids
        assert "ASVS-V14.2.1" in control_ids


class TestMapUnknownRule:
    def test_unknown_rule_returns_empty(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("semgrep", "some.unknown.rule.that.doesnt.exist")
        assert control_ids == []

    def test_unknown_scanner_returns_empty(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("unknown-scanner", "some-rule")
        assert control_ids == []


class TestMapRuleToMultipleControls:
    def test_ckv_aws_19_maps_to_two_controls(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("checkov", "CKV_AWS_19")
        assert len(control_ids) >= 2

    def test_gitleaks_any_rule_maps_to_two_controls(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("gitleaks", "any-rule-id")
        assert len(control_ids) >= 2


class TestSbomMapping:
    def test_sbom_maps_to_supply_chain_control(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("sbom", "sbom-generated")
        assert "PCI-DSS-6.3.2" in control_ids

    def test_sbom_any_rule_id_maps(self, mapper: ControlMapper) -> None:
        control_ids = mapper.map_finding("sbom", "any-rule")
        assert len(control_ids) >= 1
