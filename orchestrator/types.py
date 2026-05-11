"""Core data types for the Compliance-Driven AI Risk Platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskTier(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ProductManifest:
    """product-manifest.yaml parsed result."""

    name: str
    description: str
    data_classification: list[str]
    jurisdiction: list[str]
    deployment: dict[str, object]
    integrations: list[str] = field(default_factory=list)
    # Mission context (MbCRA — connects technical risk to business impact)
    mission: dict[str, object] = field(default_factory=dict)
    # FIPS 199 impact levels (RMF Step 2)
    impact_levels: dict[str, str] = field(default_factory=lambda: {
        "confidentiality": "moderate",
        "integrity": "moderate",
        "availability": "moderate",
    })


@dataclass
class RiskProfile:
    """risk-profile.yaml parsed result."""

    frameworks: list[str]
    risk_appetite: str
    thresholds: dict[str, dict[str, object]]
    failure_policy: dict[str, dict[str, str]]


@dataclass
class Finding:
    """Single scanner finding."""

    source: str
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    control_ids: list[str]
    product: str
    # SCA-specific fields (populated by Grype, empty for other scanners)
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""


@dataclass
class RiskReport:
    """Risk assessment result."""

    id: str
    trigger: str
    product: str
    risk_tier: RiskTier
    likelihood: str
    impact: str
    risk_score: float
    narrative: str
    findings_summary: dict[str, int]
    affected_controls: list[str]
    gate_recommendation: str
    cross_signal_insights: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class GateDecision:
    """Gate evaluation result."""

    passed: bool
    reason: str
    threshold_results: list[dict[str, object]]
    findings_count: dict[str, int]
