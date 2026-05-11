"""SP 800-30 risk assessment pipeline with two-stage AI.

4-step process (orchestrator controls every step — ADR-002):

Step 1: GATHER (no AI)
  Collect all context from existing pipeline results.

Step 2: FILTER (Haiku — fast, cheap)
  Filter findings + controls → top critical items.

Step 3: ASSESS (Sonnet — deep reasoning)
  Parallel per-finding assessment via stream_with_cache(),
  then summary synthesis. Fallback to static per-finding on failure.

Step 4: RESPOND (no AI)
  Generate risk responses + POA&M from AI assessment results.

Rules:
- AI is advisory only (ADR-004). Gate decisions are ThresholdEvaluator's job.
- InvokeModel API only (ADR-002). No Bedrock Agent.
- AI failure → per-finding static fallback (graceful degradation).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from orchestrator.assessor.bedrock_client import BedrockClient
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
from orchestrator.rmf.prompts import build_per_finding_prompts, build_summary_prompts
from orchestrator.types import Finding, ProductManifest

logger = logging.getLogger(__name__)


def _extract_json(raw: str) -> dict[str, object]:
    """Extract JSON from AI response that may be wrapped in markdown code fences."""
    text = raw.strip()
    if text.startswith("```"):
        first_newline = text.index("\n")
        last_fence = text.rfind("```")
        if last_fence > first_newline:
            text = text[first_newline + 1 : last_fence].strip()
    return json.loads(text)  # type: ignore[no-any-return]


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "very-low": 0}

_TOP_N = 5

FILTER_PROMPT = """\
You are a security analyst triaging findings for a risk assessment.

Product: {product_name} ({tier} tier, {data_classification})
Total findings: {n_findings}
Total controls: {n_controls}

Findings:
{all_findings}

Select the TOP {top_n} most critical findings for deep risk analysis.
Consider: EPSS score, CVSS severity, PCI scope, reachability.

Respond in JSON:
{{"selected_finding_indices": [0, 3, 7, 12, 15], "reasoning": "..."}}
"""

SP800_30_ASSESSMENT_PROMPT = """\
You are a security risk assessor following NIST SP 800-30 Rev 1 methodology.

## Product Context
{architecture_context}
CIA Impact: {cia_levels}

## Critical Findings (filtered)
{filtered_findings}

## Applicable Compliance Controls
{relevant_controls}

## EPSS Exploit Intelligence
{epss_data}

Perform a NIST SP 800-30 risk assessment:

1. THREAT SOURCE IDENTIFICATION (SP 800-30 Section 3.1)
   For each finding, identify the threat source:
   - Type: adversarial / accidental / structural / environmental
   - Capability: very-low / low / moderate / high / very-high
   - Intent and targeting (if adversarial)

2. THREAT EVENT IDENTIFICATION (SP 800-30 Section 3.2)
   Describe the specific threat event:
   - How would the vulnerability be exploited?
   - What ATT&CK technique applies?
   - Is it reachable in this product's code/infrastructure?

3. LIKELIHOOD DETERMINATION (SP 800-30 Section 3.3)
   Using SP 800-30 likelihood scale:
   - Initiation likelihood (how likely threat acts)
   - Impact likelihood (given action, how likely adverse impact)
   - Consider EPSS score as supporting evidence
   - Consider predisposing conditions (internet-facing, PCI scope)

4. IMPACT DETERMINATION (SP 800-30 Section 3.4)
   - Impact on confidentiality, integrity, availability
   - Compliance controls violated
   - Business impact specific to this product

5. RISK DETERMINATION (SP 800-30 Section 3.5)
   - Risk = Likelihood × Impact
   - Use SP 800-30 semi-quantitative scale (1-100)

6. RISK RESPONSE RECOMMENDATION
   - Response type: accept / avoid / mitigate / share / transfer
   - Specific remediation steps
   - Priority and timeline

Respond in JSON matching this schema:
{{
  "executive_summary": "2-3 paragraph summary for decision-makers",
  "threat_sources": [{{
    "id": "TS-XXX-NNN",
    "type": "adversarial|accidental|structural|environmental",
    "name": "...",
    "capability": "very-low|low|moderate|high|very-high",
    "intent": "...",
    "targeting": "..."
  }}],
  "threat_events": [{{
    "id": "TE-NNN",
    "description": "...",
    "source_id": "TS-XXX-NNN",
    "mitre_technique": "TNNNN",
    "relevance": "confirmed|expected|predicted|possible",
    "cve_id": "",
    "target_component": "..."
  }}],
  "likelihood_assessments": [{{
    "initiation_likelihood": "very-low|low|moderate|high|very-high",
    "impact_likelihood": "very-low|low|moderate|high|very-high",
    "overall_likelihood": "very-low|low|moderate|high|very-high",
    "epss_score": null,
    "predisposing_conditions": ["..."],
    "evidence": "..."
  }}],
  "impact_assessments": [{{
    "impact_type": "harm to operations|harm to assets|harm to individuals",
    "cia_impact": {{"confidentiality": "...", "integrity": "...", "availability": "..."}},
    "severity": "very-low|low|moderate|high|very-high",
    "compliance_impact": ["CONTROL-ID"],
    "business_impact": "...",
    "evidence": "..."
  }}],
  "risk_determinations": [{{
    "threat_event_id": "TE-NNN",
    "likelihood": "very-low|low|moderate|high|very-high",
    "impact": "very-low|low|moderate|high|very-high",
    "risk_level": "very-low|low|moderate|high|very-high",
    "risk_score": 0.0
  }}],
  "risk_responses": [{{
    "risk_determination_id": "TE-NNN",
    "response_type": "accept|avoid|mitigate|share|transfer",
    "description": "...",
    "milestones": ["..."],
    "deadline": "YYYY-MM-DD",
    "responsible": "..."
  }}],
  "recommendations": ["..."]
}}
"""


class RiskAssessmentPipeline:
    """SP 800-30 risk assessment pipeline with two-stage AI.

    AI is advisory only (ADR-004). Gate decisions are ThresholdEvaluator's job.
    InvokeModel API only (ADR-002). No Bedrock Agent.
    AI failure → per-finding static fallback (graceful degradation).
    """

    def __init__(
        self,
        bedrock_client: BedrockClient | None = None,
        haiku_model_id: str = "jp.anthropic.claude-haiku-4-5-20251001-v1:0",
    ) -> None:
        self._bedrock = bedrock_client
        self._haiku_model_id = haiku_model_id

    def run(
        self,
        findings: list[Finding],
        enriched_vulns: list[EnrichedVulnerability],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> SP80030Report:
        """Full SP 800-30 assessment pipeline.

        Falls back to static pipeline on any AI error.
        """
        try:
            gathered = self._step1_gather(
                findings, enriched_vulns, manifest, controls, trigger,
            )
            filtered = self._step2_filter(gathered)
            assessment = self._step3_assess(filtered, progress_callback=progress_callback)
            responses = self._step4_respond(assessment)

            # Determine mode from per-finding results
            per_finding = assessment.get("per_finding_results", [])
            if per_finding:
                modes = {r["mode"] for r in per_finding}
                if modes == {"ai"}:
                    mode = "ai"
                elif modes == {"static"}:
                    mode = "static"
                else:
                    mode = "hybrid"
            else:
                mode = "static"

            return self._build_report(
                manifest=manifest,
                gathered=gathered,
                assessment=assessment,
                responses=responses,
                mode=mode,
            )
        except Exception:
            logger.warning(
                "AI pipeline failed, falling back to static assessment",
                exc_info=True,
            )
            from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline

            return StaticRiskAssessmentPipeline().run(
                findings=findings,
                enriched_vulns=enriched_vulns,
                manifest=manifest,
                controls=controls,
                trigger=trigger,
            )

    def _step1_gather(
        self,
        findings: list[Finding],
        enriched_vulns: list[EnrichedVulnerability],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> dict[str, Any]:
        """Step 1: GATHER — collect all context (no AI)."""
        findings_data = [
            {
                "index": i,
                "source": f.source,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "control_ids": f.control_ids,
                "package": f.package,
                "installed_version": f.installed_version,
                "fixed_version": f.fixed_version,
            }
            for i, f in enumerate(findings)
        ]

        epss_map: dict[str, dict[str, float | str | None]] = {}
        for ev in enriched_vulns:
            epss_map[ev.cve_id] = {
                "epss_score": ev.epss_score,
                "epss_percentile": ev.epss_percentile,
                "priority": ev.priority,
            }

        controls_data = [
            {
                "id": c.id,
                "title": c.title,
                "framework": c.framework,
                "description": c.description,
            }
            for c in controls
        ]

        return {
            "findings": findings_data,
            "epss_map": epss_map,
            "controls": controls_data,
            "manifest": manifest,
            "trigger": trigger,
            "n_findings": len(findings),
            "n_controls": len(controls),
        }

    def _step2_filter(self, gathered: dict[str, Any]) -> dict[str, Any]:
        """Step 2: FILTER — select top-N findings.

        With Bedrock: Haiku selects the most critical findings.
        Without Bedrock: deterministic sort by severity.
        """
        findings = gathered["findings"]

        if self._bedrock and len(findings) > _TOP_N:
            try:
                selected_indices = self._ai_filter(gathered)
                selected = [findings[i] for i in selected_indices if i < len(findings)]
            except Exception:
                logger.warning("AI filter failed, using deterministic fallback", exc_info=True)
                selected = self._deterministic_filter(findings)
        else:
            selected = self._deterministic_filter(findings)

        # Build relevant controls from selected findings
        selected_control_ids: set[str] = set()
        for f in selected:
            selected_control_ids.update(f.get("control_ids", []))

        relevant_controls = [
            c for c in gathered["controls"]
            if c["id"] in selected_control_ids
        ]

        return {
            **gathered,
            "selected_findings": selected,
            "relevant_controls": relevant_controls,
        }

    def _step3_assess(
        self,
        filtered: dict[str, Any],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, Any]:
        """Step 3: ASSESS — parallel per-finding + summary synthesis.

        With Bedrock: parallel stream_with_cache() per finding, then summary.
        Without Bedrock: static assessment for all findings.
        Per-finding AI failures fall back to static individually.
        """
        per_finding_results = self._assess_findings_parallel(filtered, progress_callback=progress_callback)

        # Severity counts for summary
        all_findings = filtered.get("findings", filtered.get("selected_findings", []))
        severity_counts: dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = self._synthesize_summary(
            per_finding_results=per_finding_results,
            manifest=filtered["manifest"],
            total_findings=filtered.get("n_findings", len(all_findings)),
            severity_counts=severity_counts,
        )

        # Collect SP 800-30 components from per-finding results
        threat_sources = []
        threat_events = []
        likelihood_assessments = []
        impact_assessments = []
        risk_determinations = []
        risk_responses_list = []

        for r in per_finding_results:
            if "threat_source" in r:
                threat_sources.append(r["threat_source"])
            if "threat_event" in r:
                threat_events.append(r["threat_event"])
            if "likelihood" in r:
                likelihood_assessments.append(r["likelihood"])
            if "impact" in r:
                impact_assessments.append(r["impact"])
            if "risk_determination" in r:
                risk_determinations.append(r["risk_determination"])
            if "risk_response" in r:
                risk_responses_list.append(r["risk_response"])

        return {
            "per_finding_results": per_finding_results,
            "executive_summary": summary.get("executive_summary", ""),
            "cross_signal_insights": summary.get("cross_signal_insights", []),
            "overall_risk_posture": summary.get("overall_risk_posture", ""),
            "recommendations": summary.get("recommendations", []),
            "threat_sources": threat_sources,
            "threat_events": threat_events,
            "likelihood_assessments": likelihood_assessments,
            "impact_assessments": impact_assessments,
            "risk_determinations": risk_determinations,
            "risk_responses": risk_responses_list,
        }

    def _step4_respond(self, assessment: dict[str, Any]) -> list[RiskResponse]:
        """Step 4: RESPOND — generate risk responses (no AI)."""
        raw_responses = assessment.get("risk_responses", [])
        responses: list[RiskResponse] = []
        for r in raw_responses:
            if isinstance(r, RiskResponse):
                responses.append(r)
            elif isinstance(r, dict):
                responses.append(RiskResponse(
                    risk_determination_id=r.get("risk_determination_id", ""),
                    response_type=r.get("response_type", "mitigate"),
                    description=r.get("description", ""),
                    milestones=r.get("milestones", []),
                    deadline=r.get("deadline", ""),
                    responsible=r.get("responsible", "Security Engineer"),
                ))
        return responses

    # ------------------------------------------------------------------
    # Parallel per-finding assessment
    # ------------------------------------------------------------------

    def _assess_findings_parallel(
        self,
        filtered: dict[str, Any],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Assess each finding in parallel using ThreadPoolExecutor.

        Args:
            filtered: step2 output (selected_findings, relevant_controls, etc.)
            progress_callback: optional (completed, total, finding_id) -> None for CLI progress

        Returns:
            list of per-finding assessment dicts (order matches selected_findings)
        """
        selected = filtered["selected_findings"]
        manifest: ProductManifest = filtered["manifest"]
        controls = filtered.get("relevant_controls", [])
        epss_map = filtered.get("epss_map", {})
        total = len(selected)

        if not self._bedrock:
            # No Bedrock — all static
            static_results: list[dict[str, Any]] = []
            for i, finding in enumerate(selected):
                result = self._static_assess_single_finding(finding, manifest, i)
                static_results.append(result)
                if progress_callback:
                    fid = finding.get("rule_id", f"finding-{i}")
                    progress_callback(i + 1, total, fid)
            return static_results

        # Build per-finding EPSS data
        def _epss_for(finding: dict[str, Any]) -> dict[str, Any] | None:
            rule_id = finding.get("rule_id", "")
            data = epss_map.get(rule_id)
            return dict(data) if isinstance(data, dict) else None

        # Map finding controls
        def _controls_for(finding: dict[str, Any]) -> list[dict[str, Any]]:
            fids = set(finding.get("control_ids", []))
            return [c for c in controls if c["id"] in fids]

        # Submit all per-finding tasks
        results: list[dict[str, Any]] = [{}] * total  # pre-allocate ordered slots
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_index = {}
            for i, finding in enumerate(selected):
                future = executor.submit(
                    self._assess_single_finding,
                    finding=finding,
                    controls=_controls_for(finding),
                    epss_data=_epss_for(finding),
                    manifest=manifest,
                    finding_index=i,
                )
                future_to_index[future] = i

            completed_count = 0
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                completed_count += 1
                result = future.result()  # exceptions handled inside _assess_single_finding
                results[idx] = result
                if progress_callback:
                    fid = selected[idx].get("rule_id", f"finding-{idx}")
                    progress_callback(completed_count, total, fid)

        return results

    def _assess_single_finding(
        self,
        finding: dict[str, Any],
        controls: list[dict[str, Any]],
        epss_data: dict[str, Any] | None,
        manifest: ProductManifest,
        finding_index: int,
    ) -> dict[str, Any]:
        """Assess one finding via Bedrock stream_with_cache().

        On failure, falls back to static assessment for this finding only.
        """
        assert self._bedrock is not None

        try:
            system_prompt, user_prompt = build_per_finding_prompts(
                manifest=manifest,
                finding=finding,
                controls=controls,
                epss_data=epss_data,
                finding_index=finding_index,
            )

            response_text = self._bedrock.stream_with_cache(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=4096,
            )
            parsed = _extract_json(response_text)
            parsed["mode"] = "ai"
            return parsed

        except Exception:
            logger.warning(
                "AI assessment failed for finding %d, using static fallback",
                finding_index,
                exc_info=True,
            )
            return self._static_assess_single_finding(finding, manifest, finding_index)

    def _static_assess_single_finding(
        self,
        finding: dict[str, Any],
        manifest: ProductManifest,
        finding_index: int,
    ) -> dict[str, Any]:
        """Deterministic single-finding assessment (fallback).

        Uses same logic as StaticRiskAssessmentPipeline.build_assessment()
        but for a single finding.
        """
        from orchestrator.rmf.static_pipeline import (
            StaticRiskAssessmentPipeline,
            _LEVEL_SCORE,
            _SEVERITY_TO_LIKELIHOOD,
            _SOURCE_TYPE_MAP,
            _compute_static_impact,
        )

        severity = finding.get("severity", "medium")
        source = finding.get("source", "unknown")
        src_type = _SOURCE_TYPE_MAP.get(source, "adversarial")
        is_pci = "PCI" in manifest.data_classification
        control_ids = finding.get("control_ids", [])

        ts_prefix = src_type[:3].upper()
        ts_id = f"TS-{ts_prefix}-{finding_index + 1:03d}"
        te_id = f"TE-{finding_index + 1:03d}"

        sev_level = _SEVERITY_TO_LIKELIHOOD.get(severity, "moderate")
        impact_level = _compute_static_impact(severity, control_ids, is_pci, manifest)

        likelihood_val = _LEVEL_SCORE.get(sev_level, 50.0)
        impact_val = _LEVEL_SCORE.get(impact_level, 50.0)
        risk_score = (likelihood_val * impact_val) / 100.0
        risk_level = StaticRiskAssessmentPipeline._score_to_level_static(risk_score)

        msg = finding.get("message", "")

        return {
            "mode": "static",
            "threat_source": {
                "id": ts_id,
                "type": src_type,
                "name": f"{'External attacker' if src_type == 'adversarial' else 'System weakness'} — {source}",
                "capability": sev_level,
                "intent": "Financial gain" if src_type == "adversarial" else "",
                "targeting": "Targeted" if is_pci and src_type == "adversarial" else "",
            },
            "threat_event": {
                "id": te_id,
                "description": msg,
                "source_id": ts_id,
                "mitre_technique": "T1190" if "injection" in msg.lower() else "T1078",
                "relevance": "confirmed",
                "cve_id": finding.get("rule_id", "") if finding.get("rule_id", "").startswith("CVE-") else "",
                "target_component": f"{finding.get('file', '')}:{finding.get('line', 0)}",
            },
            "likelihood": {
                "initiation_likelihood": sev_level,
                "impact_likelihood": sev_level,
                "overall_likelihood": sev_level,
                "epss_score": None,
                "predisposing_conditions": ["PCI scope"] if is_pci else ["standard exposure"],
                "evidence": f"{severity.upper()} severity {source} finding",
            },
            "impact": {
                "impact_type": "harm to operations",
                "cia_impact": dict(manifest.impact_levels),
                "severity": impact_level,
                "compliance_impact": control_ids,
                "business_impact": f"{severity.upper()} finding in {manifest.name}",
                "evidence": f"Controls: {', '.join(control_ids) or 'none'}",
            },
            "risk_determination": {
                "threat_event_id": te_id,
                "likelihood": sev_level,
                "impact": impact_level,
                "risk_level": risk_level,
                "risk_score": risk_score,
            },
            "risk_response": {
                "risk_determination_id": te_id,
                "response_type": "mitigate" if severity in ("critical", "high") else "accept",
                "description": f"Remediate {source} finding: {msg}",
                "milestones": ["Identify root cause", "Apply fix", "Verify remediation"],
                "deadline": "",
                "responsible": "Security Engineer",
            },
            "narrative": f"Static assessment: {severity.upper()} {source} finding requires {'immediate' if severity in ('critical', 'high') else 'planned'} remediation.",
        }

    def _synthesize_summary(
        self,
        per_finding_results: list[dict[str, Any]],
        manifest: ProductManifest,
        total_findings: int,
        severity_counts: dict[str, int],
    ) -> dict[str, Any]:
        """Generate executive summary + cross-signal insights from all per-finding results."""
        if not self._bedrock or all(r.get("mode") == "static" for r in per_finding_results):
            return self._static_summary(per_finding_results, manifest, total_findings, severity_counts)

        try:
            system_prompt, user_prompt = build_summary_prompts(
                manifest=manifest,
                per_finding_results=per_finding_results,
                total_findings=total_findings,
                severity_counts=severity_counts,
            )

            response_text = self._bedrock.stream_with_cache(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=4096,
            )
            return _extract_json(response_text)

        except Exception:
            logger.warning("AI summary synthesis failed, using static summary", exc_info=True)
            return self._static_summary(per_finding_results, manifest, total_findings, severity_counts)

    def _static_summary(
        self,
        per_finding_results: list[dict[str, Any]],
        manifest: ProductManifest,
        total_findings: int,
        severity_counts: dict[str, int],
    ) -> dict[str, Any]:
        """Deterministic executive summary."""
        is_pci = "PCI" in manifest.data_classification
        sev_summary = ", ".join(f"{count} {sev}" for sev, count in severity_counts.items())

        recommendations = []
        if severity_counts.get("critical", 0) > 0:
            recommendations.append("Immediately remediate all critical findings")
        if severity_counts.get("high", 0) > 0:
            recommendations.append("Prioritize high-severity finding remediation")
        if is_pci:
            recommendations.append("Ensure PCI DSS compliance before next assessment")

        return {
            "executive_summary": (
                f"{manifest.name} has {total_findings} findings ({sev_summary}). "
                f"Top {len(per_finding_results)} analyzed via static assessment. "
                f"{'PCI-scoped product — critical/high findings require immediate attention.' if is_pci else ''}"
            ),
            "cross_signal_insights": [],
            "overall_risk_posture": "high" if severity_counts.get("critical", 0) > 0 else "moderate",
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # Filter step (unchanged)
    # ------------------------------------------------------------------

    def _ai_filter(self, gathered: dict[str, Any]) -> list[int]:
        """Call Haiku to select top-N findings."""
        assert self._bedrock is not None

        manifest: ProductManifest = gathered["manifest"]
        findings_text = "\n".join(
            f"[{i}] [{f['severity'].upper()}] {f['source']}: {f['message']} "
            f"({f['file']}:{f['line']}) controls={f['control_ids']}"
            for i, f in enumerate(gathered["findings"])
        )

        prompt = FILTER_PROMPT.format(
            product_name=manifest.name,
            tier="CRITICAL" if "PCI" in manifest.data_classification else "HIGH",
            data_classification=", ".join(manifest.data_classification),
            n_findings=gathered["n_findings"],
            n_controls=gathered["n_controls"],
            all_findings=findings_text,
            top_n=_TOP_N,
        )

        response_text = self._bedrock.invoke(prompt, max_tokens=1024)
        parsed = _extract_json(response_text)
        indices = parsed["selected_finding_indices"]
        return list(indices) if isinstance(indices, list) else []

    def _deterministic_filter(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort by severity and return top-N."""
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "low"), 0),
            reverse=True,
        )
        return sorted_findings[:_TOP_N]

    def _static_assess(self, filtered: dict[str, Any]) -> dict[str, Any]:
        """Deterministic SP 800-30 assessment without AI."""
        from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline

        return StaticRiskAssessmentPipeline.build_assessment(filtered)

    def _build_report(
        self,
        manifest: ProductManifest,
        gathered: dict[str, Any],
        assessment: dict[str, Any],
        responses: list[RiskResponse],
        mode: str,
    ) -> SP80030Report:
        """Assemble SP80030Report from pipeline results."""
        now = datetime.now(tz=timezone.utc)
        report_id = f"RA-SP800-30-{now.strftime('%Y-%m%d')}-001"

        threat_sources = [
            ThreatSource(**ts) if isinstance(ts, dict) else ts
            for ts in assessment.get("threat_sources", [])
        ]
        threat_events = [
            ThreatEvent(**te) if isinstance(te, dict) else te
            for te in assessment.get("threat_events", [])
        ]
        likelihood_assessments = [
            LikelihoodAssessment(**la) if isinstance(la, dict) else la
            for la in assessment.get("likelihood_assessments", [])
        ]
        impact_assessments = [
            ImpactAssessment(**ia) if isinstance(ia, dict) else ia
            for ia in assessment.get("impact_assessments", [])
        ]
        risk_determinations = [
            RiskDetermination(**rd) if isinstance(rd, dict) else rd
            for rd in assessment.get("risk_determinations", [])
        ]

        return SP80030Report(
            report_id=report_id,
            product=manifest.name,
            generated_at=now.isoformat(),
            mode=mode,
            methodology="NIST SP 800-30 Rev 1",
            scope=f"{manifest.name} full stack including IaC and dependencies",
            risk_model="semi-quantitative, threat-oriented",
            assumptions=[
                "All scanners ran successfully",
                "SBOM is complete",
                f"Trigger: {gathered['trigger']}",
            ],
            cia_impact_levels=dict(manifest.impact_levels),
            threat_sources=threat_sources,
            threat_events=threat_events,
            likelihood_assessments=likelihood_assessments,
            impact_assessments=impact_assessments,
            risk_determinations=risk_determinations,
            executive_summary=assessment.get("executive_summary", ""),
            risk_responses=responses,
            recommendations=assessment.get("recommendations", []),
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
