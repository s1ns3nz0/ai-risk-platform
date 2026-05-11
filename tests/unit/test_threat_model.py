"""Tests for threat model data format and static generator."""

from __future__ import annotations

import yaml

from orchestrator.controls.models import Control, VerificationMethod
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.intelligence.threat_model import (
    StaticThreatModelGenerator,
    ThreatActor,
    ThreatModel,
    ThreatScenario,
)
from orchestrator.types import ProductManifest, RiskTier


def _make_manifest(**overrides: object) -> ProductManifest:
    defaults: dict[str, object] = {
        "name": "payment-api",
        "description": "QR payment service",
        "data_classification": ["PCI", "PII-financial"],
        "jurisdiction": ["JP"],
        "deployment": {"cloud": "AWS", "compute": "EKS", "region": "ap-northeast-1"},
        "integrations": ["external-payment-gateway", "internal-user-db"],
    }
    defaults.update(overrides)
    return ProductManifest(**defaults)  # type: ignore[arg-type]


def _make_enriched_vuln(**overrides: object) -> EnrichedVulnerability:
    defaults: dict[str, object] = {
        "cve_id": "CVE-2022-29217",
        "severity": "critical",
        "epss_score": 0.234,
        "epss_percentile": 0.92,
        "package": "PyJWT",
        "installed_version": "1.7.1",
        "fixed_version": "2.4.0",
        "file_path": "requirements.txt",
        "control_ids": ["ASVS-V3.5.3", "PCI-DSS-8.3.1"],
        "priority": "critical",
        "product_context": "payment-api, PCI scope",
        "data_classification": ["PCI", "PII-financial"],
    }
    defaults.update(overrides)
    return EnrichedVulnerability(**defaults)  # type: ignore[arg-type]


def _make_control(**overrides: object) -> Control:
    defaults: dict[str, object] = {
        "id": "PCI-DSS-6.3.1",
        "title": "Security vulnerabilities managed",
        "framework": "PCI-DSS",
        "description": "Security vulnerabilities are identified and addressed.",
        "verification_methods": [
            VerificationMethod(scanner="semgrep", rules=["python.django.security.*"]),
        ],
        "applicable_tiers": [RiskTier.CRITICAL, RiskTier.HIGH],
    }
    defaults.update(overrides)
    return Control(**defaults)  # type: ignore[arg-type]


class TestThreatModelDataclass:
    def test_threat_model_creation(self) -> None:
        """ThreatModel 생성 + 필드 확인."""
        model = ThreatModel(
            product="payment-api",
            generated_at="2026-04-22T10:00:00Z",
            mode="static",
            components=["PyJWT 1.7.1", "requests 2.28.0"],
            architecture={"cloud": "AWS", "compute": "EKS"},
            data_classification=["PCI", "PII-financial"],
            known_vulnerabilities=["CVE-2022-29217"],
            threat_actors=[
                ThreatActor(
                    id="TA-001",
                    name="External Attacker",
                    motivation="Financial gain",
                    capability="moderate",
                    attack_surface=["internet-facing API"],
                ),
            ],
            threat_scenarios=[],
            attack_surface_summary="Internet-facing payment API",
            risk_summary="High risk due to PCI data handling",
            controls_required=["PCI-DSS-8.3.1"],
            controls_covered=["PCI-DSS-6.3.1"],
            controls_gap=["PCI-DSS-8.3.1"],
        )

        assert model.product == "payment-api"
        assert model.mode == "static"
        assert len(model.components) == 2
        assert len(model.threat_actors) == 1
        assert model.threat_actors[0].id == "TA-001"
        assert model.controls_gap == ["PCI-DSS-8.3.1"]


class TestThreatScenarioHasMitre:
    def test_scenario_has_mitre_technique(self) -> None:
        """시나리오에 ATT&CK technique 포함."""
        scenario = ThreatScenario(
            id="TS-001",
            title="JWT token forgery via algorithm confusion",
            actor="TA-001",
            attack_vector="Spoofing (STRIDE-S)",
            mitre_technique="T1078",
            target_component="PyJWT 1.7.1",
            preconditions=["Network access to /api/login"],
            attack_steps=["Obtain JWT", "Exploit algorithm confusion"],
            impact="Full access to payment processing",
            likelihood="high",
            severity="critical",
            affected_controls=["ASVS-V3.5.3", "PCI-DSS-8.3.1"],
            mitigation="Upgrade PyJWT>=2.4.0",
        )

        assert scenario.mitre_technique == "T1078"
        assert scenario.mitre_technique.startswith("T")


class TestStaticGeneratorFromVulns:
    def test_generates_scenarios_from_enriched_cves(self) -> None:
        """Enriched CVE → 위협 시나리오 생성 (EPSS > 0.1)."""
        generator = StaticThreatModelGenerator()
        manifest = _make_manifest()
        vulns = [
            _make_enriched_vuln(epss_score=0.234),  # above 0.1 → scenario
            _make_enriched_vuln(
                cve_id="CVE-2023-0001",
                epss_score=0.05,  # below 0.1 → no scenario
                package="low-risk-lib",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity="low",
                priority="low",
                control_ids=["ASVS-V14.2.1"],
            ),
        ]
        controls = [_make_control()]

        model = generator.generate(
            manifest=manifest,
            sbom_components=["PyJWT 1.7.1", "requests 2.28.0"],
            enriched_vulns=vulns,
            controls=controls,
        )

        assert model.mode == "static"
        assert len(model.threat_scenarios) >= 1
        # Only the high-EPSS vuln should generate a scenario
        scenario_cves = [s.target_component for s in model.threat_scenarios]
        assert any("CVE-2022-29217" in c for c in scenario_cves)
        # Low-EPSS vuln should NOT generate a scenario
        assert not any("CVE-2023-0001" in c for c in scenario_cves)


class TestStaticGeneratorIdentifiesAttackSurface:
    def test_identifies_attack_surface_from_manifest(self) -> None:
        """Manifest → 공격 표면 식별."""
        generator = StaticThreatModelGenerator()
        manifest = _make_manifest()

        model = generator.generate(
            manifest=manifest,
            sbom_components=["PyJWT 1.7.1"],
            enriched_vulns=[_make_enriched_vuln()],
            controls=[_make_control()],
        )

        surface = model.attack_surface_summary
        # Should identify PCI data handling and external integrations
        assert "PCI" in surface or "payment" in surface.lower()


class TestControlsGapCalculated:
    def test_controls_gap_is_required_minus_covered(self) -> None:
        """필요 컨트롤 vs 커버 컨트롤 gap 계산."""
        generator = StaticThreatModelGenerator()
        manifest = _make_manifest()
        vulns = [
            _make_enriched_vuln(
                control_ids=["ASVS-V3.5.3", "PCI-DSS-8.3.1"],
            ),
        ]
        controls = [
            _make_control(id="PCI-DSS-6.3.1"),
            _make_control(id="ASVS-V3.5.3"),
        ]

        model = generator.generate(
            manifest=manifest,
            sbom_components=["PyJWT 1.7.1"],
            enriched_vulns=vulns,
            controls=controls,
        )

        # controls_required comes from scenario affected_controls
        # controls_covered comes from the controls list ids
        # controls_gap = required - covered
        assert "PCI-DSS-8.3.1" in model.controls_gap
        assert "ASVS-V3.5.3" not in model.controls_gap


class TestOutputYamlFormat:
    def test_threat_model_serializes_to_yaml(self) -> None:
        """YAML 출력 포맷 검증."""
        generator = StaticThreatModelGenerator()
        manifest = _make_manifest()
        vulns = [_make_enriched_vuln()]
        controls = [_make_control()]

        model = generator.generate(
            manifest=manifest,
            sbom_components=["PyJWT 1.7.1", "requests 2.28.0"],
            enriched_vulns=vulns,
            controls=controls,
        )

        output = model.to_yaml()
        parsed = yaml.safe_load(output)

        assert "threat_model" in parsed
        tm = parsed["threat_model"]
        assert tm["product"] == "payment-api"
        assert tm["mode"] == "static"
        assert "threat_actors" in tm
        assert "threat_scenarios" in tm
        assert "controls_gap" in tm
        assert "risk_summary" in tm
