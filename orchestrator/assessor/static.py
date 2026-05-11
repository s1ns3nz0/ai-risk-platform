"""StaticRiskAssessor — deterministic risk assessment without AI (ADR-004)."""

from __future__ import annotations

import itertools
from datetime import datetime, timezone
from pathlib import Path

import yaml

from orchestrator.controls.models import Control
from orchestrator.scoring.risk import compute_risk_score
from orchestrator.types import Finding, ProductManifest, RiskReport, RiskTier

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_REPORT_COUNTER = itertools.count(1)


def _generate_report_id() -> str:
    """RA-YYYY-MMDD-NNN 형식의 report ID 생성."""
    now = datetime.now(tz=timezone.utc)
    seq = next(_REPORT_COUNTER)
    return f"RA-{now.year}-{now.month:02d}{now.day:02d}-{seq:03d}"


def _score_to_label(score: float) -> str:
    if score >= 8.0:
        return "very-high"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "very-low"


def _gate_recommendation(score: float) -> str:
    if score >= 7.0:
        return "BLOCK"
    if score >= 4.0:
        return "REVIEW"
    return "PROCEED"


class StaticRiskAssessor:
    """AI 없이 동작하는 risk assessor. Deterministic 로직만 사용한다."""

    def __init__(self, compliance_mappings_path: str | None = None) -> None:
        self._mappings: dict[str, dict[str, object]] = self._load_compliance_mappings(compliance_mappings_path)

    @staticmethod
    def _load_compliance_mappings(path: str | None = None) -> dict[str, dict[str, object]]:
        """Load compliance-mappings.yaml. Falls back to defaults if missing."""
        if path is None:
            path = str(_PROJECT_ROOT / "controls" / "compliance-mappings.yaml")
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            # Fallback: no mappings → everything is LOW
            return {
                "data_classifications": {},
                "jurisdictions": {},
                "tier_thresholds": {"critical": 3, "high": 2, "medium": 1, "low": 0},
            }

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """Categorization driven by compliance-mappings.yaml (deterministic).

        Logic:
        1. Collect required frameworks from data_classification mappings
        2. Collect additional frameworks from jurisdiction mappings
        3. Count distinct frameworks
        4. Map count to tier via tier_thresholds
        """
        required_frameworks: set[str] = set()

        # Data classification → frameworks
        class_mappings: dict[str, object] = self._mappings.get("data_classifications", {})
        for dc in manifest.data_classification:
            key = dc.upper()
            entry = class_mappings.get(key, class_mappings.get(dc, {}))
            if isinstance(entry, dict):
                fws = entry.get("frameworks", [])
                if isinstance(fws, list):
                    required_frameworks.update(str(fw) for fw in fws)

        # Jurisdiction → additional frameworks
        jurisdiction_mappings: dict[str, object] = self._mappings.get("jurisdictions", {})
        for j in manifest.jurisdiction:
            key = j.upper()
            entry = jurisdiction_mappings.get(key, jurisdiction_mappings.get(j, {}))
            if isinstance(entry, dict):
                fws = entry.get("frameworks", [])
                if isinstance(fws, list):
                    required_frameworks.update(str(fw) for fw in fws)

        # Count distinct frameworks → tier
        thresholds: dict[str, object] = self._mappings.get("tier_thresholds", {})
        count = len(required_frameworks)

        def _int(val: object, default: int) -> int:
            try:
                return int(str(val))
            except (ValueError, TypeError):
                return default

        critical_threshold = _int(thresholds.get("critical", 3), 3)
        high_threshold = _int(thresholds.get("high", 2), 2)
        medium_threshold = _int(thresholds.get("medium", 1), 1)

        if count >= critical_threshold:
            tier = RiskTier.CRITICAL
        elif count >= high_threshold:
            tier = RiskTier.HIGH
        elif count >= medium_threshold:
            tier = RiskTier.MEDIUM
        else:
            tier = RiskTier.LOW

        # FIPS 199: all-high CIA elevates tier by one step (supplementary, not gate)
        if all(
            manifest.impact_levels.get(dim) == "high"
            for dim in ("confidentiality", "integrity", "availability")
        ):
            _TIER_ORDER = [RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL]
            idx = _TIER_ORDER.index(tier)
            if idx < len(_TIER_ORDER) - 1:
                tier = _TIER_ORDER[idx + 1]

        return tier

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> RiskReport:
        """Static assessment: compute_risk_score + 템플릿 narrative."""
        score, factors = compute_risk_score(findings, manifest, controls)

        severity_dist: dict[str, int] = factors["finding_severity_distribution"]  # type: ignore[assignment]
        likelihood_score = float(factors["likelihood_score"])  # type: ignore[arg-type]
        impact_score = float(factors["impact_score"])  # type: ignore[arg-type]
        affected_controls = sorted(
            {cid for f in findings for cid in f.control_ids}
        )

        narrative = (
            f"Risk Assessment for {manifest.name}: {trigger} trigger. "
            f"Found {severity_dist['critical']} critical, {severity_dist['high']} high "
            f"findings across {len(controls)} controls. "
            f"Data classification: {', '.join(sorted(manifest.data_classification))}. "
            f"Risk score: {score:.1f}/10. "
            f"Gate recommendation: {_gate_recommendation(score)}."
        )

        return RiskReport(
            id=_generate_report_id(),
            trigger=trigger,
            product=manifest.name,
            risk_tier=self.categorize(manifest),
            likelihood=_score_to_label(likelihood_score),
            impact=_score_to_label(impact_score),
            risk_score=score,
            narrative=narrative,
            findings_summary=severity_dist,
            affected_controls=affected_controls,
            gate_recommendation=_gate_recommendation(score),
        )
