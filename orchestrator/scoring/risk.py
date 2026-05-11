"""Likelihood × Impact risk scoring — SP 800-30 aligned."""

from __future__ import annotations

import math

from orchestrator.controls.models import Control
from orchestrator.types import Finding, ProductManifest

_DATA_CLASSIFICATION_WEIGHT: dict[str, float] = {
    "PCI": 10.0,
    "PII-FINANCIAL": 8.0,
    "PII-GENERAL": 5.0,
    "PUBLIC": 1.0,
}

_JURISDICTION_WEIGHT: dict[str, float] = {
    "JP": 9.0,  # FISC
    "EU": 7.0,  # GDPR
}
_JURISDICTION_DEFAULT = 3.0

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}


def compute_risk_score(
    findings: list[Finding],
    manifest: ProductManifest,
    controls: list[Control],
) -> tuple[float, dict[str, object]]:
    """Likelihood × Impact 기반 risk score 계산.

    Returns:
        (risk_score 0-10, factors dict with evidence per factor)
    """
    # --- Likelihood factors ---
    severity_dist: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity.lower()
        if key in severity_dist:
            severity_dist[key] += 1

    total_findings = len(findings)

    # Weighted severity score (0-10)
    if total_findings > 0:
        weighted = sum(severity_dist.get(s, 0) * _SEVERITY_WEIGHT.get(s, 0) for s in severity_dist)
        severity_score = min(weighted / total_findings, 10.0)
        # Logarithmic volume factor — differentiates 10 vs 100 vs 1000 findings
        # log10(10)=1.0, log10(100)=2.0, log10(1000)=3.0
        # Factor range: 1.0 (1 finding) to 2.0 (1000+ findings)
        volume_factor = min(1.0 + math.log10(max(total_findings, 1)) * 0.3, 2.0)
        severity_score = min(severity_score * volume_factor, 10.0)
    else:
        severity_score = 0.0
        volume_factor = 1.0

    # PCI scope ratio
    pci_findings = sum(
        1 for f in findings if any(cid.startswith("PCI-DSS") for cid in f.control_ids)
    )
    pci_scope_ratio = pci_findings / total_findings if total_findings > 0 else 0.0

    # Secrets detected — scales with count, caps at 4.0
    secrets_count = sum(1 for f in findings if f.source == "gitleaks")
    secrets_detected = secrets_count > 0
    secrets_bonus = min(secrets_count * 0.5, 4.0) if secrets_detected else 0.0

    likelihood_score = min(severity_score + secrets_bonus + pci_scope_ratio, 10.0)

    # --- Impact factors ---
    classifications = {c.upper() for c in manifest.data_classification}
    max_class_weight = max(
        (_DATA_CLASSIFICATION_WEIGHT.get(c, 1.0) for c in classifications),
        default=1.0,
    )

    # Control coverage
    required_control_ids = {c.id for c in controls}
    covered_control_ids: set[str] = set()
    for f in findings:
        covered_control_ids.update(cid for cid in f.control_ids if cid in required_control_ids)
    control_coverage = (
        len(covered_control_ids) / len(required_control_ids) if required_control_ids else 1.0
    )
    # More coverage of controls with findings = higher impact (more areas affected)
    coverage_impact = control_coverage * 3.0

    # Jurisdiction sensitivity
    jurisdiction_score = max(
        (_JURISDICTION_WEIGHT.get(j.upper(), _JURISDICTION_DEFAULT) for j in manifest.jurisdiction),
        default=_JURISDICTION_DEFAULT,
    )

    impact_score = min(
        (max_class_weight * 0.6 + jurisdiction_score * 0.2 + coverage_impact * 0.2),
        10.0,
    )

    # --- Combined score ---
    risk_score = round(min(likelihood_score * 0.5 + impact_score * 0.5, 10.0), 1)

    factors: dict[str, object] = {
        "finding_severity_distribution": severity_dist,
        "total_findings": total_findings,
        "volume_factor": round(volume_factor, 2),
        "pci_scope_ratio": round(pci_scope_ratio, 2),
        "secrets_detected": secrets_detected,
        "secrets_count": secrets_count,
        "data_classification": sorted(classifications),
        "control_coverage": round(control_coverage, 2),
        "jurisdiction_sensitivity": jurisdiction_score,
        "likelihood_score": round(likelihood_score, 2),
        "impact_score": round(impact_score, 2),
    }

    return risk_score, factors
