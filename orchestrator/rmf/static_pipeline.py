"""SP 800-30 assessment without AI.

Uses deterministic logic + templates when Bedrock is unavailable.
Same SP80030Report output format — just less nuanced.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from orchestrator.controls.models import Control
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.rmf.models import (
    ImpactAssessment,
    LikelihoodAssessment,
    RiskDetermination,
    RiskResponse,
    SP80030Report,
    ThreatEvent,
    ThreatSource,
)
from orchestrator.types import Finding, ProductManifest

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "very-low": 0}

# SP 800-30 semi-quantitative scale mapping
_LEVEL_SCORE: dict[str, float] = {
    "very-high": 96.0,
    "high": 80.0,
    "moderate": 50.0,
    "low": 20.0,
    "very-low": 4.0,
}

# Severity → SP 800-30 likelihood level
_SEVERITY_TO_LIKELIHOOD: dict[str, str] = {
    "critical": "very-high",
    "high": "high",
    "medium": "moderate",
    "low": "low",
}

# Threat source type mapping based on finding source
_SOURCE_TYPE_MAP: dict[str, str] = {
    "semgrep": "adversarial",
    "gitleaks": "adversarial",
    "grype": "structural",
    "checkov": "structural",
}


class StaticRiskAssessmentPipeline:
    """SP 800-30 assessment without AI.

    Uses deterministic logic + templates when Bedrock is unavailable.
    Same SP80030Report output format — just less nuanced.
    """

    def run(
        self,
        findings: list[Finding],
        enriched_vulns: list[EnrichedVulnerability],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
        progress_callback: object = None,
    ) -> SP80030Report:
        """Template-based SP 800-30 assessment."""
        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )
        top_findings = sorted_findings[:5]

        # Build EPSS map
        epss_map: dict[str, float | None] = {
            ev.cve_id: ev.epss_score for ev in enriched_vulns
        }

        # Build assessment components
        threat_sources: list[ThreatSource] = []
        threat_events: list[ThreatEvent] = []
        likelihood_assessments: list[LikelihoodAssessment] = []
        impact_assessments: list[ImpactAssessment] = []
        risk_determinations: list[RiskDetermination] = []
        risk_responses: list[RiskResponse] = []

        is_pci = "PCI" in manifest.data_classification
        source_counter: dict[str, int] = {}

        for i, finding in enumerate(top_findings):
            src_type = _SOURCE_TYPE_MAP.get(finding.source, "adversarial")
            source_counter.setdefault(src_type, 0)
            source_counter[src_type] += 1
            ts_idx = source_counter[src_type]

            ts_prefix = src_type[:3].upper()
            ts_id = f"TS-{ts_prefix}-{ts_idx:03d}"
            te_id = f"TE-{i + 1:03d}"

            # Threat source
            ts = ThreatSource(
                id=ts_id,
                type=src_type,
                name=f"{'External attacker' if src_type == 'adversarial' else 'System weakness'} — {finding.source}",
                capability=_SEVERITY_TO_LIKELIHOOD.get(finding.severity, "moderate"),
                intent="Financial gain via data theft" if src_type == "adversarial" else "",
                targeting="Targeted" if is_pci and src_type == "adversarial" else "",
            )
            threat_sources.append(ts)

            # Threat event
            cve_id = finding.rule_id if finding.rule_id.startswith("CVE-") else ""
            te = ThreatEvent(
                id=te_id,
                description=finding.message,
                source_id=ts_id,
                mitre_technique="T1190" if "injection" in finding.message.lower() else "T1078",
                relevance="confirmed",
                cve_id=cve_id,
                target_component=f"{finding.file}:{finding.line}",
            )
            threat_events.append(te)

            # Likelihood
            severity_level = _SEVERITY_TO_LIKELIHOOD.get(finding.severity, "moderate")
            epss = epss_map.get(finding.rule_id)
            conditions = []
            if is_pci:
                conditions.append("PCI scope")
            if any(cid.startswith("PCI-DSS") for cid in finding.control_ids):
                conditions.append("PCI control violated")

            la = LikelihoodAssessment(
                initiation_likelihood=severity_level,
                impact_likelihood=severity_level,
                overall_likelihood=severity_level,
                epss_score=epss,
                predisposing_conditions=conditions or ["standard exposure"],
                evidence=f"{finding.severity.upper()} severity {finding.source} finding"
                + (f", EPSS={epss:.4f}" if epss else ""),
            )
            likelihood_assessments.append(la)

            # Impact
            impact_level = self._compute_impact_level(finding, manifest)
            ia = ImpactAssessment(
                impact_type="harm to operations",
                cia_impact=dict(manifest.impact_levels),
                severity=impact_level,
                compliance_impact=finding.control_ids,
                business_impact=f"{finding.severity.upper()} finding in {'PCI-scoped' if is_pci else ''} {manifest.name}",
                evidence=f"Controls affected: {', '.join(finding.control_ids) or 'none'}",
            )
            impact_assessments.append(ia)

            # Risk determination — Likelihood × Impact
            likelihood_score = _LEVEL_SCORE.get(severity_level, 50.0)
            impact_score = _LEVEL_SCORE.get(impact_level, 50.0)
            risk_score = (likelihood_score * impact_score) / 100.0
            risk_level = self._score_to_level(risk_score)

            rd = RiskDetermination(
                threat_event_id=te_id,
                likelihood=severity_level,
                impact=impact_level,
                risk_level=risk_level,
                risk_score=risk_score,
            )
            risk_determinations.append(rd)

            # Risk response
            rr = RiskResponse(
                risk_determination_id=te_id,
                response_type="mitigate" if finding.severity in ("critical", "high") else "accept",
                description=f"Remediate {finding.source} finding: {finding.message}",
                milestones=["Identify root cause", "Apply fix", "Verify remediation"],
                deadline="",
                responsible="Security Engineer",
            )
            risk_responses.append(rr)

        # Build severity summary for narrative
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        sev_summary = ", ".join(f"{count} {sev}" for sev, count in sorted(
            sev_counts.items(),
            key=lambda x: _SEVERITY_ORDER.get(x[0], 0),
            reverse=True,
        ))

        executive_summary = (
            f"{manifest.name} has {len(findings)} findings ({sev_summary}). "
            f"{'PCI-scoped product requires immediate attention for critical/high findings. ' if is_pci else ''}"
            f"Risk assessment covers {len(controls)} applicable controls across "
            f"{len(set(c.framework for c in controls))} frameworks."
        )

        recommendations = []
        if sev_counts.get("critical", 0) > 0:
            recommendations.append("Immediately remediate all critical findings")
        if sev_counts.get("high", 0) > 0:
            recommendations.append("Prioritize high-severity finding remediation")
        if is_pci:
            recommendations.append("Ensure PCI DSS compliance before next assessment")

        now = datetime.now(tz=timezone.utc)
        report_id = f"RA-SP800-30-{now.strftime('%Y-%m%d')}-001"

        return SP80030Report(
            report_id=report_id,
            product=manifest.name,
            generated_at=now.isoformat(),
            mode="static",
            methodology="NIST SP 800-30 Rev 1",
            scope=f"{manifest.name} full stack including IaC and dependencies",
            risk_model="semi-quantitative, threat-oriented",
            assumptions=[
                "All scanners ran successfully",
                "SBOM is complete",
                f"Trigger: {trigger}",
            ],
            cia_impact_levels=dict(manifest.impact_levels),
            threat_sources=threat_sources,
            threat_events=threat_events,
            likelihood_assessments=likelihood_assessments,
            impact_assessments=impact_assessments,
            risk_determinations=risk_determinations,
            executive_summary=executive_summary,
            risk_responses=risk_responses,
            recommendations=recommendations,
            reassessment_triggers=[
                "New critical CVE in dependency",
                "Architecture change",
                "Compliance framework update",
            ],
            next_review_date=(
                datetime(now.year, now.month + 3 if now.month <= 9 else now.month - 9,
                         now.day, tzinfo=timezone.utc).strftime("%Y-%m-%d")
                if now.month <= 9
                else datetime(now.year + 1, now.month - 9,
                              now.day, tzinfo=timezone.utc).strftime("%Y-%m-%d")
            ),
        )

    @staticmethod
    def build_assessment(filtered: dict[str, Any]) -> dict[str, Any]:
        """Build static assessment dict from filtered pipeline data.

        Used by RiskAssessmentPipeline when Bedrock is unavailable.
        """
        manifest: ProductManifest = filtered["manifest"]
        selected = filtered.get("selected_findings", [])
        is_pci = "PCI" in manifest.data_classification
        epss_map = filtered.get("epss_map", {})

        threat_sources = []
        threat_events = []
        likelihood_assessments = []
        impact_assessments = []
        risk_determinations = []
        risk_responses = []

        source_counter: dict[str, int] = {}

        for i, f in enumerate(selected):
            severity = f.get("severity", "medium")
            source = f.get("source", "unknown")
            src_type = _SOURCE_TYPE_MAP.get(source, "adversarial")
            source_counter.setdefault(src_type, 0)
            source_counter[src_type] += 1

            ts_prefix = src_type[:3].upper()
            ts_id = f"TS-{ts_prefix}-{source_counter[src_type]:03d}"
            te_id = f"TE-{i + 1:03d}"

            threat_sources.append({
                "id": ts_id,
                "type": src_type,
                "name": f"{'External attacker' if src_type == 'adversarial' else 'System weakness'} — {source}",
                "capability": _SEVERITY_TO_LIKELIHOOD.get(severity, "moderate"),
                "intent": "Financial gain" if src_type == "adversarial" else "",
                "targeting": "Targeted" if is_pci and src_type == "adversarial" else "",
            })

            cve_id = f.get("rule_id", "") if f.get("rule_id", "").startswith("CVE-") else ""
            msg = f.get("message", "")
            threat_events.append({
                "id": te_id,
                "description": msg,
                "source_id": ts_id,
                "mitre_technique": "T1190" if "injection" in msg.lower() else "T1078",
                "relevance": "confirmed",
                "cve_id": cve_id,
                "target_component": f"{f.get('file', '')}:{f.get('line', 0)}",
            })

            sev_level = _SEVERITY_TO_LIKELIHOOD.get(severity, "moderate")
            epss = epss_map.get(f.get("rule_id", ""), {})
            epss_score = epss.get("epss_score") if isinstance(epss, dict) else None

            conditions = []
            if is_pci:
                conditions.append("PCI scope")

            likelihood_assessments.append({
                "initiation_likelihood": sev_level,
                "impact_likelihood": sev_level,
                "overall_likelihood": sev_level,
                "epss_score": epss_score,
                "predisposing_conditions": conditions or ["standard exposure"],
                "evidence": f"{severity.upper()} severity {source} finding",
            })

            control_ids = f.get("control_ids", [])
            impact_level = _compute_static_impact(severity, control_ids, is_pci, manifest)

            impact_assessments.append({
                "impact_type": "harm to operations",
                "cia_impact": dict(manifest.impact_levels),
                "severity": impact_level,
                "compliance_impact": control_ids,
                "business_impact": f"{severity.upper()} finding in {manifest.name}",
                "evidence": f"Controls: {', '.join(control_ids) or 'none'}",
            })

            likelihood_val = _LEVEL_SCORE.get(sev_level, 50.0)
            impact_val = _LEVEL_SCORE.get(impact_level, 50.0)
            risk_score = (likelihood_val * impact_val) / 100.0
            risk_level = StaticRiskAssessmentPipeline._score_to_level_static(risk_score)

            risk_determinations.append({
                "threat_event_id": te_id,
                "likelihood": sev_level,
                "impact": impact_level,
                "risk_level": risk_level,
                "risk_score": risk_score,
            })

            risk_responses.append({
                "risk_determination_id": te_id,
                "response_type": "mitigate" if severity in ("critical", "high") else "accept",
                "description": f"Remediate {source} finding: {msg}",
                "milestones": ["Identify root cause", "Apply fix", "Verify remediation"],
                "deadline": "",
                "responsible": "Security Engineer",
            })

        n_findings = filtered.get("n_findings", len(selected))
        executive_summary = (
            f"{manifest.name} has {n_findings} total findings. "
            f"Top {len(selected)} analyzed via static assessment. "
            f"{'PCI-scoped product — critical/high findings require immediate attention.' if is_pci else ''}"
        )

        recommendations = []
        severities = [f.get("severity", "") for f in selected]
        if "critical" in severities:
            recommendations.append("Immediately remediate all critical findings")
        if "high" in severities:
            recommendations.append("Prioritize high-severity finding remediation")
        if is_pci:
            recommendations.append("Ensure PCI DSS compliance before next assessment")

        return {
            "executive_summary": executive_summary,
            "threat_sources": threat_sources,
            "threat_events": threat_events,
            "likelihood_assessments": likelihood_assessments,
            "impact_assessments": impact_assessments,
            "risk_determinations": risk_determinations,
            "risk_responses": risk_responses,
            "recommendations": recommendations,
        }

    @staticmethod
    def _compute_impact_level(finding: Finding, manifest: ProductManifest) -> str:
        """Compute impact level from finding severity and product context."""
        is_pci = "PCI" in manifest.data_classification
        has_pci_control = any(cid.startswith("PCI-DSS") for cid in finding.control_ids)

        if finding.severity == "critical" and is_pci:
            return "very-high"
        if finding.severity == "critical" or (finding.severity == "high" and has_pci_control):
            return "high"
        if finding.severity == "high":
            return "high"
        if finding.severity == "medium":
            return "moderate"
        return "low"

    @staticmethod
    def _score_to_level(score: float) -> str:
        if score >= 80:
            return "very-high"
        if score >= 55:
            return "high"
        if score >= 30:
            return "moderate"
        if score >= 10:
            return "low"
        return "very-low"

    @staticmethod
    def _score_to_level_static(score: float) -> str:
        if score >= 80:
            return "very-high"
        if score >= 55:
            return "high"
        if score >= 30:
            return "moderate"
        if score >= 10:
            return "low"
        return "very-low"


def _compute_static_impact(
    severity: str,
    control_ids: list[str],
    is_pci: bool,
    manifest: ProductManifest,
) -> str:
    has_pci_control = any(cid.startswith("PCI-DSS") for cid in control_ids)
    if severity == "critical" and is_pci:
        return "very-high"
    if severity == "critical" or (severity == "high" and has_pci_control):
        return "high"
    if severity == "high":
        return "high"
    if severity == "medium":
        return "moderate"
    return "low"
