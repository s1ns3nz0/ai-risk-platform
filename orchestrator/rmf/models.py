"""SP 800-30 Rev 1 risk assessment data models.

Implements the 4-phase structure of NIST SP 800-30:
  Phase 1 — Prepare: scope, risk model, assumptions
  Phase 2 — Conduct: threat sources, events, likelihood, impact, risk determinations
  Phase 3 — Communicate: executive summary, risk responses, recommendations
  Phase 4 — Maintain: reassessment triggers, next review date
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ThreatSource:
    """SP 800-30 Table D-1: Threat source identification."""

    id: str
    type: str  # adversarial | accidental | structural | environmental
    name: str  # "External attacker" / "Insider" / "System failure"
    capability: str  # very-low / low / moderate / high / very-high
    intent: str  # SP 800-30 Table D-2 (adversarial only)
    targeting: str  # SP 800-30 Table D-3 (adversarial only)


@dataclass
class ThreatEvent:
    """SP 800-30 Table E: Threat event identification."""

    id: str
    description: str
    source_id: str  # ThreatSource reference
    mitre_technique: str  # ATT&CK mapping
    relevance: str  # confirmed / expected / predicted / possible
    cve_id: str  # CVE if applicable
    target_component: str  # SBOM component or code path


@dataclass
class LikelihoodAssessment:
    """SP 800-30 Table G-3 through G-6."""

    initiation_likelihood: str  # very-low / low / moderate / high / very-high
    impact_likelihood: str  # given initiation, likelihood of adverse impact
    overall_likelihood: str  # combined
    epss_score: float | None  # EPSS exploit probability (supplementary)
    predisposing_conditions: list[str]  # "internet-facing", "PCI scope", etc.
    evidence: str  # reasoning for the determination


@dataclass
class ImpactAssessment:
    """SP 800-30 Table G-7 through G-9."""

    impact_type: str  # harm to operations / assets / individuals / nation
    cia_impact: dict[str, str]  # {confidentiality: high, integrity: high, ...}
    severity: str  # very-low / low / moderate / high / very-high
    compliance_impact: list[str]  # controls violated
    business_impact: str  # business consequence description
    evidence: str


@dataclass
class RiskDetermination:
    """SP 800-30 Table G-10: Risk = Likelihood x Impact."""

    threat_event_id: str
    likelihood: str  # from LikelihoodAssessment
    impact: str  # from ImpactAssessment
    risk_level: str  # very-low / low / moderate / high / very-high
    risk_score: float  # 0-100 semi-quantitative


@dataclass
class RiskResponse:
    """SP 800-30 risk response."""

    risk_determination_id: str
    response_type: str  # accept / avoid / mitigate / share / transfer
    description: str
    milestones: list[str]  # remediation steps
    deadline: str  # target completion date
    responsible: str  # role responsible


@dataclass
class SP80030Report:
    """Complete SP 800-30 risk assessment report."""

    report_id: str  # RA-SP800-30-YYYY-MMDD-NNN
    product: str
    generated_at: str
    mode: str  # "ai" | "static" | "hybrid"
    methodology: str  # "NIST SP 800-30 Rev 1"

    # Phase 1: Prepare
    scope: str
    risk_model: str  # "semi-quantitative, threat-oriented"
    assumptions: list[str]
    cia_impact_levels: dict[str, str]

    # Phase 2: Conduct
    threat_sources: list[ThreatSource]
    threat_events: list[ThreatEvent]
    likelihood_assessments: list[LikelihoodAssessment]
    impact_assessments: list[ImpactAssessment]
    risk_determinations: list[RiskDetermination]

    # Phase 3: Communicate
    executive_summary: str
    risk_responses: list[RiskResponse]
    recommendations: list[str] = field(default_factory=list)

    # Phase 4: Maintain
    reassessment_triggers: list[str] = field(default_factory=list)
    next_review_date: str = ""
