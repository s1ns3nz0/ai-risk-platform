"""Vulnerability enrichment — combines EPSS scores with compliance context.

Takes raw Grype findings and produces EnrichedVulnerability objects.
This is enrichment only — does NOT make gate decisions.
"""

from __future__ import annotations

from orchestrator.intelligence.epss import EpssClient
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding, ProductManifest

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class VulnerabilityEnricher:
    """Enriches Grype CVE findings with EPSS scores and compliance context.

    Takes raw Grype findings and produces EnrichedVulnerability objects with:
    - EPSS exploit probability
    - Compliance control mapping
    - Priority scoring (EPSS × CVSS × compliance context)
    - Product context for AI analysis
    """

    def __init__(self, epss_client: EpssClient, control_mapper: ControlMapper) -> None:
        self._epss_client = epss_client
        self._control_mapper = control_mapper

    def enrich(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
    ) -> list[EnrichedVulnerability]:
        """Enrich Grype findings with exploit intelligence.

        Priority scoring:
        - When EPSS available:
          - CRITICAL: EPSS > 0.5 OR (CVSS critical AND PCI scope)
          - HIGH: EPSS > 0.1 OR CVSS high
          - MEDIUM: EPSS > 0.01
          - LOW: EPSS <= 0.01
        - When EPSS unavailable: fall back to CVSS severity directly
          (critical stays critical, high stays high — don't downgrade)
        """
        cve_ids = [f.rule_id for f in findings if f.rule_id.startswith("CVE-")]
        epss_scores = self._epss_client.get_scores(cve_ids) if cve_ids else {}

        is_pci = "PCI" in manifest.data_classification
        product_context = self._build_product_context(manifest)

        enriched: list[EnrichedVulnerability] = []
        for finding in findings:
            epss = epss_scores.get(finding.rule_id)
            epss_score = epss.epss if epss else None
            epss_percentile = epss.percentile if epss else None

            priority = self._compute_priority(
                severity=finding.severity,
                epss_score=epss_score,
                is_pci=is_pci,
                control_ids=finding.control_ids,
            )

            enriched.append(
                EnrichedVulnerability(
                    cve_id=finding.rule_id,
                    severity=finding.severity,
                    epss_score=epss_score,
                    epss_percentile=epss_percentile,
                    package=finding.package,
                    installed_version=finding.installed_version,
                    fixed_version=finding.fixed_version,
                    file_path=finding.file,
                    control_ids=finding.control_ids,
                    priority=priority,
                    product_context=product_context,
                    data_classification=manifest.data_classification,
                )
            )

        return enriched

    def sort_by_priority(
        self, vulns: list[EnrichedVulnerability]
    ) -> list[EnrichedVulnerability]:
        """Sort by EPSS (descending), then CVSS severity."""
        return sorted(vulns, key=self._sort_key, reverse=True)

    @staticmethod
    def _compute_priority(
        severity: str,
        epss_score: float | None,
        is_pci: bool,
        control_ids: list[str],
    ) -> str:
        has_pci_control = any(cid.startswith("PCI-DSS") for cid in control_ids)
        in_pci_scope = is_pci and has_pci_control

        # EPSS unavailable → fall back to CVSS severity directly
        if epss_score is None:
            if severity == "critical" and in_pci_scope:
                return "critical"
            return severity

        # EPSS available — use thresholds
        if epss_score > 0.5:
            return "critical"
        if severity == "critical" and in_pci_scope:
            return "critical"
        if epss_score > 0.1 or severity == "high":
            return "high"
        if epss_score > 0.01:
            return "medium"
        return "low"

    @staticmethod
    def _sort_key(vuln: EnrichedVulnerability) -> tuple[int, float, int]:
        pri = _SEVERITY_ORDER.get(vuln.priority, 0)
        epss = vuln.epss_score if vuln.epss_score is not None else -1.0
        sev = _SEVERITY_ORDER.get(vuln.severity, 0)
        return (pri, epss, sev)

    @staticmethod
    def _build_product_context(manifest: ProductManifest) -> str:
        parts = [manifest.name]
        if "PCI" in manifest.data_classification:
            parts.append("PCI scope")
        cloud = manifest.deployment.get("cloud")
        if cloud:
            parts.append(str(cloud))
        if manifest.jurisdiction:
            parts.append(", ".join(manifest.jurisdiction))
        return ", ".join(parts)
