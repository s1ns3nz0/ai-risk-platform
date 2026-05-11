"""Dashboard-optimized JSON exporter.

Pure function — no AI, no network calls. Only side effect is file writes.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.rmf.models import SP80030Report
from orchestrator.rmf.poam import AuthorizationDecision, POAMItem
from orchestrator.rmf.sar import SecurityAssessmentReport


def _json_dump(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _build_risk_distribution(report: SP80030Report) -> dict[str, int]:
    """Count risk determinations by level."""
    dist: dict[str, int] = {
        "very-high": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
        "very-low": 0,
    }
    for rd in report.risk_determinations:
        if rd.risk_level in dist:
            dist[rd.risk_level] += 1
    return dist


def _overall_risk(report: SP80030Report) -> str:
    """Worst risk level from determinations, or 'low' if none."""
    order = {"very-high": 4, "high": 3, "moderate": 2, "low": 1, "very-low": 0}
    worst = "low"
    worst_val = -1
    for rd in report.risk_determinations:
        val = order.get(rd.risk_level, -1)
        if val > worst_val:
            worst_val = val
            worst = rd.risk_level
    return worst


def _build_index(
    report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
    pipeline_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build lightweight index.json for dashboard landing view."""
    # POA&M severity breakdown
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in poam_items:
        if item.severity in by_severity:
            by_severity[item.severity] += 1

    # Nearest deadline
    deadlines = [item.scheduled_completion for item in poam_items if item.scheduled_completion]
    nearest_deadline = min(deadlines) if deadlines else ""

    # Total findings from threat events count
    total_findings = len(report.threat_events)
    assessed_findings = len(report.risk_determinations)

    index: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product": report.product,
        "mode": report.mode,
        "risk_posture": {
            "overall": _overall_risk(report),
            "risk_distribution": _build_risk_distribution(report),
            "total_findings": total_findings,
            "assessed_findings": assessed_findings,
        },
        "gate": {
            "decision": authorization.decision,
            "reasoning": authorization.reasoning,
            "valid_until": authorization.valid_until,
        },
        "sar_summary": {
            "total_controls": sar.total_controls,
            "satisfied": sar.satisfied,
            "other_than_satisfied": sar.other_than_satisfied,
            "not_assessed": sar.not_assessed,
            "coverage_pct": sar.coverage_percentage,
        },
        "poam_summary": {
            "total_items": len(poam_items),
            "by_severity": by_severity,
            "nearest_deadline": nearest_deadline,
        },
        "pipeline": pipeline_metadata or {},
    }
    return index


def export_dashboard(
    report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
    output_dir: str,
    pipeline_metadata: dict[str, Any] | None = None,
) -> list[str]:
    """Export dashboard-optimized JSON files.

    Writes:
      {output_dir}/dashboard/index.json        — pipeline summary (~2KB)
      {output_dir}/dashboard/sp800-30.json      — full SP 800-30 report
      {output_dir}/dashboard/sar.json            — control assessments
      {output_dir}/dashboard/poam.json           — action items
      {output_dir}/dashboard/authorization.json  — ATO decision

    Returns: list of written file paths.
    """
    dashboard_dir = Path(output_dir, "dashboard")
    dashboard_dir.mkdir(parents=True, exist_ok=True)

    files: list[str] = []

    # index.json — lightweight summary
    index_path = dashboard_dir / "index.json"
    index_data = _build_index(report, sar, poam_items, authorization, pipeline_metadata)
    index_path.write_text(_json_dump(index_data))
    files.append(str(index_path))

    # sp800-30.json — full report
    sp800_path = dashboard_dir / "sp800-30.json"
    sp800_path.write_text(_json_dump(asdict(report)))
    files.append(str(sp800_path))

    # sar.json — control assessments
    sar_path = dashboard_dir / "sar.json"
    sar_path.write_text(_json_dump(asdict(sar)))
    files.append(str(sar_path))

    # poam.json — action items
    poam_path = dashboard_dir / "poam.json"
    poam_data = {
        "items": [asdict(item) for item in poam_items],
        "total": len(poam_items),
    }
    poam_path.write_text(_json_dump(poam_data))
    files.append(str(poam_path))

    # authorization.json — ATO decision
    auth_path = dashboard_dir / "authorization.json"
    auth_path.write_text(_json_dump(asdict(authorization)))
    files.append(str(auth_path))

    return files
