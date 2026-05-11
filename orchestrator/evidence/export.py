"""Evidence report generator — JSONL + Controls Repository -> audit-ready report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from orchestrator.controls.models import Control
from orchestrator.controls.repository import ControlsRepository
from orchestrator.evidence.jsonl import JsonlWriter

if TYPE_CHECKING:
    from orchestrator.integrations.defectdojo import DefectDojoClient


class EvidenceExporter:
    """Evidence report generator.

    Generates audit-ready reports from JSONL + Controls Repository.

    Data source priority:
    1. DefectDojo (if available) — source of truth
    2. JSONL (fallback) — always available

    - Evidence is a generated artifact, not a DB (ADR-008).
    - Control ID is the primary key across the entire platform.
    - MVP-0: JSON format only.
    """

    def __init__(
        self,
        jsonl_reader: JsonlWriter,
        controls_repo: ControlsRepository,
        defectdojo_client: DefectDojoClient | None = None,
    ) -> None:
        self._jsonl = jsonl_reader
        self._controls = controls_repo
        self._dd = defectdojo_client

    def export(
        self,
        product: str,
        control_id: str | None = None,
        period: str | None = None,
        output_path: str = "output/evidence",
    ) -> dict[str, Any]:
        """Generate an evidence report."""
        now = datetime.now(timezone.utc)
        report_id = f"EVD-{now.strftime('%Y-%m%d')}-001"

        # Determine which controls to include
        if control_id is not None:
            controls_map = {
                cid: ctrl
                for cid, ctrl in self._controls.controls.items()
                if cid == control_id
            }
        else:
            controls_map = dict(self._controls.controls)

        # Read findings: prefer DefectDojo, fallback to JSONL
        all_findings, data_source = self._load_findings(product, control_id)

        # Build per-control evidence
        control_entries: list[dict[str, Any]] = []
        fully_evidenced = 0
        partially_evidenced = 0
        no_evidence = 0

        for cid, ctrl in controls_map.items():
            ctrl_findings = [
                f for f in all_findings if cid in f.get("data", {}).get("control_ids", [])
            ]
            status = self._determine_control_status(ctrl, ctrl_findings)

            scanners_used = sorted({f["data"]["source"] for f in ctrl_findings})
            last_scan = (
                max(f["timestamp"] for f in ctrl_findings) if ctrl_findings else None
            )

            entry: dict[str, Any] = {
                "control_id": cid,
                "title": ctrl.title,
                "framework": ctrl.framework,
                "status": status,
                "evidence": {
                    "findings": [f["data"] for f in ctrl_findings],
                    "scanners_used": scanners_used,
                    "last_scan": last_scan,
                    "data_source": data_source,
                    "risk_assessments": [],
                },
            }
            control_entries.append(entry)

            if status == "full":
                fully_evidenced += 1
            elif status == "partial":
                partially_evidenced += 1
            else:
                no_evidence += 1

        total = len(controls_map)
        coverage = round((fully_evidenced + partially_evidenced) / total * 100, 1) if total > 0 else 0.0

        # Build executive summary: findings-by-control
        total_mapped_findings = sum(len(e["evidence"]["findings"]) for e in control_entries)
        total_all_findings = len(all_findings)
        unmapped_count = total_all_findings - total_mapped_findings

        controls_summary: list[dict[str, Any]] = []
        for entry in control_entries:
            n_findings = len(entry["evidence"]["findings"])
            severity_dist: dict[str, int] = {}
            for f in entry["evidence"]["findings"]:
                sev = f.get("severity", "unknown")
                severity_dist[sev] = severity_dist.get(sev, 0) + 1
            controls_summary.append({
                "control_id": entry["control_id"],
                "title": entry["title"],
                "status": entry["status"],
                "findings_count": n_findings,
                "severity_distribution": severity_dist,
                "scanners": entry["evidence"]["scanners_used"],
            })

        # Scanner health metadata
        scanner_health: dict[str, object] = {}
        try:
            from orchestrator.scanners.grype import check_grype_db_freshness

            scanner_health["grype_db"] = check_grype_db_freshness()
        except Exception:
            scanner_health["grype_db"] = {"status": "unavailable"}

        report: dict[str, Any] = {
            "report_id": report_id,
            "generated_at": now.isoformat(),
            "product": product,
            "period": period,
            "scanner_health": scanner_health,
            "executive_summary": {
                "total_controls": total,
                "fully_evidenced": fully_evidenced,
                "partially_evidenced": partially_evidenced,
                "no_evidence": no_evidence,
                "coverage_percentage": coverage,
                "total_findings": total_all_findings,
                "mapped_to_controls": total_mapped_findings,
                "unmapped_findings": unmapped_count,
                "controls": controls_summary,
            },
            "controls": control_entries,
            "summary": {
                "total_controls": total,
                "fully_evidenced": fully_evidenced,
                "partially_evidenced": partially_evidenced,
                "no_evidence": no_evidence,
                "coverage_percentage": coverage,
            },
        }

        # Write JSON file
        out_dir = Path(output_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{report_id}.json"
        with open(out_file, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report

    def _load_findings(
        self, product: str, control_id: str | None = None
    ) -> tuple[list[dict[str, Any]], str]:
        """Load findings from DefectDojo (preferred) or JSONL (fallback).

        Returns (findings_list, data_source_name).
        """
        if self._dd is not None:
            try:
                if self._dd.health_check():
                    tags = [control_id] if control_id else None
                    dd_findings = self._dd.get_findings(product, tags=tags)
                    return (
                        [self._dd_finding_to_jsonl_entry(f) for f in dd_findings],
                        "defectdojo",
                    )
            except Exception:
                pass  # DefectDojo error → fallback to JSONL

        return self._jsonl.read_findings(product=product, control_id=control_id), "jsonl"

    @staticmethod
    def _dd_finding_to_jsonl_entry(dd_finding: dict[str, Any]) -> dict[str, Any]:
        """Convert a DefectDojo finding dict to JSONL-compatible entry format."""
        severity_map = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "Info": "info"}
        return {
            "type": "finding",
            "timestamp": dd_finding.get("created", ""),
            "data": {
                "source": "defectdojo",
                "rule_id": dd_finding.get("title", ""),
                "severity": severity_map.get(dd_finding.get("severity", ""), "info"),
                "file": dd_finding.get("file_path", ""),
                "line": dd_finding.get("line", 0),
                "message": dd_finding.get("description", ""),
                "control_ids": dd_finding.get("tags", []),
                "product": "",
            },
        }

    def _determine_control_status(self, control: Control, findings: list[dict[str, Any]]) -> str:
        """Determine evidence status for a control.

        - "full": all verification_methods have recent scan results
        - "partial": some verification_methods have scan results
        - "none": no scan results
        """
        if not findings:
            return "none"

        required_scanners = {vm.scanner for vm in control.verification_methods}
        found_scanners = {f["data"]["source"] for f in findings}
        covered = required_scanners & found_scanners

        # Findings from non-required scanners (e.g., Sigma rules with control_ids)
        # count as supplementary evidence — upgrade "none" to "partial"
        has_supplementary = bool(found_scanners - required_scanners) and bool(findings)

        if not covered:
            return "partial" if has_supplementary else "none"
        if covered == required_scanners:
            return "full"
        return "partial"
