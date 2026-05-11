"""Tests for VulnerabilityEnricher — EPSS + compliance context enrichment."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from orchestrator.intelligence.enricher import VulnerabilityEnricher
from orchestrator.intelligence.epss import EpssScore
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.types import Finding, ProductManifest


def _make_manifest(**overrides: object) -> ProductManifest:
    defaults: dict[str, object] = {
        "name": "payment-api",
        "description": "QR payment service",
        "data_classification": ["PCI", "PII-financial"],
        "jurisdiction": ["JP"],
        "deployment": {"type": "ecs", "environment": "production"},
        "integrations": [],
    }
    defaults.update(overrides)
    return ProductManifest(**defaults)  # type: ignore[arg-type]


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "source": "grype",
        "rule_id": "CVE-2024-1234",
        "severity": "high",
        "file": "requirements.txt",
        "line": 0,
        "message": "vuln in requests",
        "control_ids": ["PCI-DSS-6.3.1"],
        "product": "payment-api",
        "package": "requests",
        "installed_version": "2.28.0",
        "fixed_version": "2.31.0",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


@pytest.fixture()
def epss_client() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def control_mapper() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def enricher(epss_client: MagicMock, control_mapper: MagicMock) -> VulnerabilityEnricher:
    return VulnerabilityEnricher(epss_client=epss_client, control_mapper=control_mapper)


class TestEnrichAddsEpssScore:
    def test_enrich_adds_epss_score(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        epss_client.get_scores.return_value = {
            "CVE-2024-1234": EpssScore(
                cve="CVE-2024-1234", epss=0.42, percentile=0.95, date="2026-04-22"
            ),
        }
        findings = [_make_finding()]
        manifest = _make_manifest()

        result = enricher.enrich(findings, manifest)

        assert len(result) == 1
        assert result[0].epss_score == 0.42
        assert result[0].epss_percentile == 0.95


class TestPriorityCriticalWhenEpssHigh:
    def test_priority_critical_when_epss_above_half(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        epss_client.get_scores.return_value = {
            "CVE-2024-1234": EpssScore(
                cve="CVE-2024-1234", epss=0.67, percentile=0.99, date="2026-04-22"
            ),
        }
        findings = [_make_finding(severity="medium")]
        manifest = _make_manifest()

        result = enricher.enrich(findings, manifest)

        assert result[0].priority == "critical"


class TestPriorityFallbackToCvssWhenEpssUnavailable:
    def test_priority_falls_back_to_cvss_severity(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        """EPSS None → priority equals CVSS severity (no downgrade)."""
        epss_client.get_scores.return_value = {}
        findings = [_make_finding(severity="high")]
        manifest = _make_manifest()

        result = enricher.enrich(findings, manifest)

        assert result[0].epss_score is None
        assert result[0].priority == "high"

    def test_critical_cvss_stays_critical_without_epss(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        epss_client.get_scores.return_value = {}
        findings = [_make_finding(severity="critical")]
        manifest = _make_manifest()

        result = enricher.enrich(findings, manifest)

        assert result[0].priority == "critical"


class TestEnrichPreservesControlIds:
    def test_control_ids_from_finding_are_preserved(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        epss_client.get_scores.return_value = {}
        findings = [_make_finding(control_ids=["PCI-DSS-6.3.1", "ASVS-V14.2.1"])]
        manifest = _make_manifest()

        result = enricher.enrich(findings, manifest)

        assert result[0].control_ids == ["PCI-DSS-6.3.1", "ASVS-V14.2.1"]


class TestSortByPriority:
    def test_sort_epss_descending_then_severity(
        self, enricher: VulnerabilityEnricher
    ) -> None:
        vulns = [
            EnrichedVulnerability(
                cve_id="CVE-LOW",
                severity="low",
                epss_score=0.01,
                epss_percentile=0.10,
                package="a",
                installed_version="1.0",
                fixed_version="2.0",
                file_path="req.txt",
                control_ids=[],
                priority="low",
                product_context="",
                data_classification=[],
            ),
            EnrichedVulnerability(
                cve_id="CVE-HIGH-EPSS",
                severity="medium",
                epss_score=0.80,
                epss_percentile=0.99,
                package="b",
                installed_version="1.0",
                fixed_version="2.0",
                file_path="req.txt",
                control_ids=[],
                priority="critical",
                product_context="",
                data_classification=[],
            ),
            EnrichedVulnerability(
                cve_id="CVE-NO-EPSS",
                severity="critical",
                epss_score=None,
                epss_percentile=None,
                package="c",
                installed_version="1.0",
                fixed_version="2.0",
                file_path="req.txt",
                control_ids=[],
                priority="critical",
                product_context="",
                data_classification=[],
            ),
        ]

        sorted_vulns = enricher.sort_by_priority(vulns)

        assert sorted_vulns[0].cve_id == "CVE-HIGH-EPSS"
        assert sorted_vulns[1].cve_id == "CVE-NO-EPSS"
        assert sorted_vulns[2].cve_id == "CVE-LOW"


class TestPciScopeElevatesPriority:
    def test_pci_scope_critical_cvss_without_epss(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        """PCI scope + CVSS critical → priority=critical even without EPSS."""
        epss_client.get_scores.return_value = {}
        findings = [
            _make_finding(
                severity="critical",
                control_ids=["PCI-DSS-6.3.1"],
            )
        ]
        manifest = _make_manifest(data_classification=["PCI", "PII-financial"])

        result = enricher.enrich(findings, manifest)

        assert result[0].priority == "critical"

    def test_pci_scope_elevates_high_cvss_with_low_epss(
        self, enricher: VulnerabilityEnricher, epss_client: MagicMock
    ) -> None:
        """PCI scope + CVSS critical + low EPSS → still critical."""
        epss_client.get_scores.return_value = {
            "CVE-2024-1234": EpssScore(
                cve="CVE-2024-1234", epss=0.005, percentile=0.30, date="2026-04-22"
            ),
        }
        findings = [
            _make_finding(
                severity="critical",
                control_ids=["PCI-DSS-6.3.1"],
            )
        ]
        manifest = _make_manifest(data_classification=["PCI"])

        result = enricher.enrich(findings, manifest)

        assert result[0].priority == "critical"
