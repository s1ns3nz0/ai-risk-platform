"""Tests for config parsers."""

from __future__ import annotations

import os

import pytest
import yaml
from jsonschema import ValidationError

from orchestrator.config.manifest import load_manifest
from orchestrator.config.profile import load_profile
from orchestrator.types import ProductManifest, RiskProfile

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "products", "payment-api")


class TestLoadManifest:
    def test_load_valid_manifest(self) -> None:
        path = os.path.join(FIXTURES_DIR, "product-manifest.yaml")
        manifest = load_manifest(path)
        assert isinstance(manifest, ProductManifest)
        assert manifest.name == "payment-api"
        assert manifest.data_classification == ["PCI", "PII-financial"]
        assert manifest.deployment["cloud"] == "AWS"
        assert "external-payment-gateway" in manifest.integrations

    def test_missing_required_field(self, tmp_path: object) -> None:
        bad_yaml = {"product": {"name": "test"}}
        path = os.path.join(str(tmp_path), "bad.yaml")
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)
        with pytest.raises(ValidationError):
            load_manifest(path)

    def test_missing_product_key(self, tmp_path: object) -> None:
        bad_yaml = {"name": "test"}
        path = os.path.join(str(tmp_path), "bad.yaml")
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)
        with pytest.raises(ValidationError):
            load_manifest(path)


class TestLoadProfile:
    def test_load_valid_profile(self) -> None:
        path = os.path.join(FIXTURES_DIR, "risk-profile.yaml")
        profile = load_profile(path)
        assert isinstance(profile, RiskProfile)
        assert profile.risk_appetite == "conservative"
        assert "pci-dss-4.0" in profile.frameworks
        assert profile.thresholds["critical"]["action"] == "block"
        assert profile.failure_policy["low"]["scan_failure"] == "proceed"

    def test_missing_required_field(self, tmp_path: object) -> None:
        bad_yaml = {"risk_profile": {"frameworks": ["pci"]}}
        path = os.path.join(str(tmp_path), "bad.yaml")
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)
        with pytest.raises(ValidationError):
            load_profile(path)

    def test_invalid_risk_appetite(self, tmp_path: object) -> None:
        bad_yaml = {
            "risk_profile": {
                "frameworks": ["pci"],
                "risk_appetite": "reckless",
                "thresholds": {},
                "failure_policy": {},
            }
        }
        path = os.path.join(str(tmp_path), "bad.yaml")
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)
        with pytest.raises(ValidationError):
            load_profile(path)

    def test_missing_risk_profile_key(self, tmp_path: object) -> None:
        bad_yaml = {"frameworks": ["pci"]}
        path = os.path.join(str(tmp_path), "bad.yaml")
        with open(path, "w") as f:
            yaml.dump(bad_yaml, f)
        with pytest.raises(ValidationError):
            load_profile(path)
