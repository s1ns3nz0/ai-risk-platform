"""Controls Repository — loads OSCAL YAML controls and selects baselines."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.types import ProductManifest, RiskTier

_TIER_LOOKUP = {t.value: t for t in RiskTier}


def _parse_verification_method(data: dict[str, Any]) -> VerificationMethod:
    return VerificationMethod(
        scanner=data["scanner"],
        rules=data.get("rules"),
        check_ids=data.get("check_ids"),
        severity_threshold=data.get("severity_threshold"),
    )


def _parse_control(data: dict[str, Any]) -> Control:
    c = data["control"]
    return Control(
        id=c["id"],
        title=c["title"],
        framework=c["framework"],
        description=c["description"],
        verification_methods=[_parse_verification_method(vm) for vm in c["verification_methods"]],
        applicable_tiers=[_TIER_LOOKUP[t] for t in c["applicable_tiers"]],
        risk_tier_mapping=c.get("risk_tier_mapping", {}),
    )


class ControlsRepository:
    """Controls Repository — YAML 파일에서 컨트롤을 로드하고 baseline을 선택한다."""

    def __init__(self, baselines_dir: str, tier_mappings_path: str) -> None:
        self.baselines_dir = Path(baselines_dir)
        self.tier_mappings_path = Path(tier_mappings_path)
        self.controls: dict[str, Control] = {}
        self._tier_mappings: dict[str, dict[str, Any]] = {}
        self._framework_controls: dict[str, list[Control]] = {}

    def load_all(self) -> None:
        """baselines_dir의 모든 YAML 파일을 로드한다."""
        # Load tier mappings
        with open(self.tier_mappings_path) as f:
            raw = yaml.safe_load(f)
        self._tier_mappings = raw["tier_mappings"]

        # Load all baseline YAML files
        self.controls.clear()
        self._framework_controls.clear()

        for yaml_path in sorted(self.baselines_dir.glob("*.yaml")):
            with open(yaml_path) as f:
                data = yaml.safe_load(f)
            for entry in data.get("controls", []):
                control = _parse_control(entry)
                self.controls[control.id] = control
                self._framework_controls.setdefault(control.framework, []).append(control)

    def get_control(self, control_id: str) -> Control:
        """Control ID로 단일 컨트롤을 반환한다."""
        return self.controls[control_id]

    def get_baseline_for_tier(self, tier: RiskTier) -> list[Control]:
        """tier-mappings.yaml에 따라 해당 tier에 적용되는 모든 컨트롤을 반환한다."""
        mapping = self._tier_mappings.get(tier.value, {})
        frameworks: list[str] = mapping.get("frameworks", [])

        result: list[Control] = []
        for fw in frameworks:
            for control in self._framework_controls.get(fw, []):
                if tier in control.applicable_tiers and control.risk_tier_mapping.get(tier.value) != "not-required":
                    result.append(control)
        return result

    def get_controls_for_product(self, manifest: ProductManifest) -> list[Control]:
        """ProductManifest의 data_classification + jurisdiction으로 적용 가능한 컨트롤을 반환한다."""
        # Determine applicable frameworks from product context
        applicable_frameworks: set[str] = set()
        classifications = {c.upper() for c in manifest.data_classification}

        if "PCI" in classifications or "PII-FINANCIAL" in classifications:
            applicable_frameworks.add("pci-dss-4.0")
        applicable_frameworks.add("asvs-4.0.3-L3")

        if "JP" in manifest.jurisdiction:
            applicable_frameworks.add("fisc-safety")

        result: list[Control] = []
        for fw in applicable_frameworks:
            result.extend(self._framework_controls.get(fw, []))
        return result

    def get_verification_methods(self, control_id: str, scanner: str) -> list[dict[str, Any]]:
        """특정 컨트롤의 특정 scanner에 대한 verification method를 반환한다."""
        control = self.controls[control_id]  # raises KeyError if not found
        result: list[dict[str, Any]] = []
        for vm in control.verification_methods:
            if vm.scanner == scanner:
                method: dict[str, Any] = {"scanner": vm.scanner}
                if vm.rules is not None:
                    method["rules"] = vm.rules
                if vm.check_ids is not None:
                    method["check_ids"] = vm.check_ids
                if vm.severity_threshold is not None:
                    method["severity_threshold"] = vm.severity_threshold
                result.append(method)
        return result
