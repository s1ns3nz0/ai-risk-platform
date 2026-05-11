"""Tests for FIPS 199 CIA impact levels (RMF Step 2)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from orchestrator.assessor.prompts import _format_architecture_context
from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.config.manifest import load_manifest
from orchestrator.types import ProductManifest, RiskTier


def _make_manifest(
    impact_levels: dict[str, str] | None = None,
    data_classification: list[str] | None = None,
    jurisdiction: list[str] | None = None,
) -> ProductManifest:
    kwargs: dict = {
        "name": "test-product",
        "description": "test",
        "data_classification": data_classification or ["PII-general"],
        "jurisdiction": jurisdiction or ["US"],
        "deployment": {"cloud": "AWS", "region": "us-east-1"},
        "integrations": [],
    }
    if impact_levels is not None:
        kwargs["impact_levels"] = impact_levels
    return ProductManifest(**kwargs)


def test_manifest_has_default_impact_levels() -> None:
    """impact_levels 없는 manifest → 기본값 moderate/moderate/moderate."""
    m = ProductManifest(
        name="x",
        description="x",
        data_classification=["public"],
        jurisdiction=["US"],
        deployment={},
    )
    assert m.impact_levels == {
        "confidentiality": "moderate",
        "integrity": "moderate",
        "availability": "moderate",
    }


def test_manifest_parses_impact_levels(tmp_path: Path) -> None:
    """impact_levels 있는 YAML → 파싱 확인."""
    manifest_yaml = tmp_path / "product-manifest.yaml"
    manifest_yaml.write_text(
        textwrap.dedent("""\
            product:
              name: test-api
              description: "Test API"
              data_classification:
                - PCI
              jurisdiction:
                - JP
              deployment:
                cloud: AWS
                region: ap-northeast-1
              impact_levels:
                confidentiality: high
                integrity: high
                availability: low
        """)
    )
    m = load_manifest(str(manifest_yaml))
    assert m.impact_levels == {
        "confidentiality": "high",
        "integrity": "high",
        "availability": "low",
    }


def test_manifest_parses_without_impact_levels(tmp_path: Path) -> None:
    """impact_levels 없는 YAML → 기본값 사용 (하위 호환)."""
    manifest_yaml = tmp_path / "product-manifest.yaml"
    manifest_yaml.write_text(
        textwrap.dedent("""\
            product:
              name: legacy-api
              description: "Legacy"
              data_classification:
                - public
              jurisdiction:
                - US
              deployment:
                cloud: AWS
                region: us-east-1
        """)
    )
    m = load_manifest(str(manifest_yaml))
    assert m.impact_levels == {
        "confidentiality": "moderate",
        "integrity": "moderate",
        "availability": "moderate",
    }


def test_all_high_cia_elevates_tier() -> None:
    """C/I/A 모두 high → tier 한 단계 상승."""
    assessor = StaticRiskAssessor()

    # With default compliance-mappings, PII-general + US → MEDIUM tier normally
    manifest_medium = _make_manifest(
        impact_levels={"confidentiality": "moderate", "integrity": "moderate", "availability": "moderate"},
        data_classification=["PII-general"],
        jurisdiction=["US"],
    )
    base_tier = assessor.categorize(manifest_medium)

    manifest_elevated = _make_manifest(
        impact_levels={"confidentiality": "high", "integrity": "high", "availability": "high"},
        data_classification=["PII-general"],
        jurisdiction=["US"],
    )
    elevated_tier = assessor.categorize(manifest_elevated)

    # Elevated tier should be one step higher
    tier_order = [RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL]
    base_idx = tier_order.index(base_tier)
    elevated_idx = tier_order.index(elevated_tier)
    assert elevated_idx == min(base_idx + 1, 3)  # capped at CRITICAL


def test_all_high_cia_does_not_exceed_critical() -> None:
    """이미 CRITICAL인 경우 CIA all-high여도 CRITICAL 유지."""
    assessor = StaticRiskAssessor()

    # PCI + JP → CRITICAL normally
    manifest = _make_manifest(
        impact_levels={"confidentiality": "high", "integrity": "high", "availability": "high"},
        data_classification=["PCI", "PII-financial"],
        jurisdiction=["JP"],
    )
    tier = assessor.categorize(manifest)
    assert tier == RiskTier.CRITICAL


def test_cia_in_architecture_context() -> None:
    """AI 프롬프트에 CIA impact levels 포함."""
    m = _make_manifest(
        impact_levels={"confidentiality": "high", "integrity": "high", "availability": "moderate"},
    )
    context = _format_architecture_context(m)
    assert "Impact Levels (FIPS 199)" in context
    assert "Confidentiality: HIGH" in context
    assert "Integrity: HIGH" in context
    assert "Availability: MODERATE" in context
