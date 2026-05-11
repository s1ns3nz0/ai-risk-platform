"""Control and VerificationMethod data models."""

from __future__ import annotations

from dataclasses import dataclass, field

from orchestrator.types import RiskTier


@dataclass
class VerificationMethod:
    """Scanner-specific verification configuration for a control."""

    scanner: str
    rules: list[str] | None = None
    check_ids: list[str] | None = None
    severity_threshold: str | None = None


@dataclass
class Control:
    """Single compliance control from the controls repository."""

    id: str
    title: str
    framework: str
    description: str
    verification_methods: list[VerificationMethod]
    applicable_tiers: list[RiskTier]
    risk_tier_mapping: dict[str, str] = field(default_factory=dict)
