"""Data models for vulnerability intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnrichedVulnerability:
    """CVE finding enriched with exploit intelligence."""

    cve_id: str
    severity: str  # from Grype (CVSS-based)
    epss_score: float | None  # exploit probability (0-1)
    epss_percentile: float | None  # position vs all CVEs
    package: str  # affected package name
    installed_version: str  # version in use
    fixed_version: str  # version that fixes it
    file_path: str  # where in the codebase
    control_ids: list[str]  # compliance controls affected
    priority: str  # computed: critical/high/medium/low

    # Context for AI analysis (Step 2)
    product_context: str  # "payment-api, PCI scope, internet-facing"
    data_classification: list[str] = field(default_factory=list)  # ["PCI", "PII-financial"]
