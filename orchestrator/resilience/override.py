"""OverrideManager — override mechanism for high/critical tier scan failures."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from orchestrator.evidence.jsonl import JsonlWriter

logger = logging.getLogger(__name__)

OVERRIDE_REASONS = [
    "scanner_service_down",
    "scanner_timeout",
    "false_positive_confirmed",
    "emergency_hotfix",
]


@dataclass
class OverrideRecord:
    """Override 기록 — evidence chain에 포함."""

    id: str  # OVR-YYYY-MMDD-NNN
    product: str
    tier: str
    failed_scanners: list[str]
    reason: str  # predefined category
    justification: str  # free text
    approver: str  # who approved (or "force-override" in demo mode)
    timestamp: str  # ISO format
    deferred_scan_sla: str  # SLA deadline ISO timestamp


class OverrideManager:
    """Override mechanism for high/critical tier scan failures.

    Red Team decisions:
    - Demo: --force-override flag (no approval workflow)
    - Production: integrate with GitHub PR reviews (documented, not built)
    - Override recorded in JSONL for evidence chain
    - SLA: deferred scan must complete within configured hours
    - SLA breach: product risk tier elevated one level

    핵심 규칙:
    - Override는 high/critical tier에서만 사용 가능
    - Override 사유는 predefined categories + free text
    - Override는 항상 JSONL에 기록 (audit trail)
    """

    _counter: int = 0

    def __init__(self, jsonl_writer: JsonlWriter) -> None:
        self._jsonl_writer = jsonl_writer

    def create_override(
        self,
        product: str,
        tier: str,
        failed_scanners: list[str],
        reason: str,
        justification: str,
        approver: str = "force-override",
        sla_hours: int = 4,
    ) -> OverrideRecord:
        """Override를 생성하고 JSONL에 기록.

        reason은 OVERRIDE_REASONS 중 하나여야 함.
        """
        if reason not in OVERRIDE_REASONS:
            raise ValueError(
                f"Invalid override reason: '{reason}'. Must be one of {OVERRIDE_REASONS}"
            )

        now = datetime.now(timezone.utc)
        sla_deadline = now + timedelta(hours=sla_hours)

        OverrideManager._counter += 1
        override_id = f"OVR-{now.strftime('%Y-%m%d')}-{OverrideManager._counter:03d}"

        record = OverrideRecord(
            id=override_id,
            product=product,
            tier=tier,
            failed_scanners=failed_scanners,
            reason=reason,
            justification=justification,
            approver=approver,
            timestamp=now.isoformat(),
            deferred_scan_sla=sla_deadline.isoformat(),
        )

        entry = {
            "type": "override",
            "timestamp": record.timestamp,
            "data": {
                "id": record.id,
                "product": record.product,
                "tier": record.tier,
                "failed_scanners": record.failed_scanners,
                "reason": record.reason,
                "justification": record.justification,
                "approver": record.approver,
                "deferred_scan_sla": record.deferred_scan_sla,
            },
        }
        self._jsonl_writer._append(entry)

        logger.info("Override created: %s for %s (%s)", override_id, product, reason)
        return record

    def get_pending_overrides(self, product: str | None = None) -> list[OverrideRecord]:
        """JSONL에서 override 목록 조회."""
        if not self._jsonl_writer.output_path.exists():
            return []

        results: list[OverrideRecord] = []
        for line in self._jsonl_writer.output_path.read_text().strip().splitlines():
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("type") != "override":
                continue

            data = entry["data"]
            if product is not None and data["product"] != product:
                continue

            results.append(
                OverrideRecord(
                    id=data["id"],
                    product=data["product"],
                    tier=data["tier"],
                    failed_scanners=data["failed_scanners"],
                    reason=data["reason"],
                    justification=data["justification"],
                    approver=data["approver"],
                    timestamp=entry["timestamp"],
                    deferred_scan_sla=data["deferred_scan_sla"],
                )
            )
        return results
