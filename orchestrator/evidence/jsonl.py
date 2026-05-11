"""Append-only JSONL evidence writer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.types import Finding, GateDecision, RiskReport


class JsonlWriter:
    """Append-only JSONL file writer.

    - Always writes to a local file (no network).
    - Each entry includes timestamp and finding hash.
    - Finding hash = hash(source + file + line + rule_id + commit_sha).
    - This file serves as DefectDojo backup + debug log + evidence source.
    """

    def __init__(self, output_path: str) -> None:
        self.output_path = Path(output_path)

    def write_finding(self, finding: Finding, commit_sha: str = "") -> None:
        """Append a single finding to JSONL."""
        hash_input = f"{finding.source}:{finding.file}:{finding.line}:{finding.rule_id}:{commit_sha}"
        entry_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        entry: dict[str, Any] = {
            "type": "finding",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hash": entry_hash,
            "data": {
                "source": finding.source,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "message": finding.message,
                "control_ids": finding.control_ids,
                "product": finding.product,
            },
        }
        self._append(entry)

    def write_findings(self, findings: list[Finding], commit_sha: str = "") -> None:
        """Append multiple findings to JSONL."""
        for finding in findings:
            self.write_finding(finding, commit_sha=commit_sha)

    def write_risk_report(self, report: RiskReport) -> None:
        """Append a risk report to JSONL."""
        entry: dict[str, Any] = {
            "type": "risk_report",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "id": report.id,
                "product": report.product,
                "risk_tier": report.risk_tier.value,
                "risk_score": report.risk_score,
                "narrative": report.narrative,
                "findings_summary": report.findings_summary,
                "affected_controls": report.affected_controls,
                "gate_recommendation": report.gate_recommendation,
            },
        }
        self._append(entry)

    def write_gate_decision(self, decision: GateDecision, product: str) -> None:
        """Append a gate decision to JSONL."""
        entry: dict[str, Any] = {
            "type": "gate_decision",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "passed": decision.passed,
                "reason": decision.reason,
                "threshold_results": decision.threshold_results,
                "findings_count": decision.findings_count,
                "product": product,
            },
        }
        self._append(entry)

    def read_findings(
        self,
        product: str | None = None,
        control_id: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read findings from JSONL with optional filters."""
        if not self.output_path.exists():
            return []

        results: list[dict[str, Any]] = []
        for line in self.output_path.read_text().strip().splitlines():
            if not line:
                continue
            entry: dict[str, Any] = json.loads(line)
            if entry.get("type") != "finding":
                continue

            data = entry.get("data", {})
            if product is not None and data.get("product") != product:
                continue
            if control_id is not None and control_id not in data.get("control_ids", []):
                continue
            if since is not None and entry.get("timestamp", "") < since:
                continue

            results.append(entry)
        return results

    def _append(self, entry: dict[str, Any]) -> None:
        """Append a single JSON entry as a line to the JSONL file."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
