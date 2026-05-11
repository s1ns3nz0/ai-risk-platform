"""Tests for OverrideManager — override mechanism for scan failures."""

from __future__ import annotations

import json
import re
from datetime import datetime

import pytest

from orchestrator.evidence.jsonl import JsonlWriter
from orchestrator.resilience.override import (
    OverrideManager,
    OverrideRecord,
)


@pytest.fixture()
def jsonl_writer(tmp_path: object) -> JsonlWriter:
    from pathlib import Path

    return JsonlWriter(str(Path(str(tmp_path)) / "findings.jsonl"))


@pytest.fixture()
def manager(jsonl_writer: JsonlWriter) -> OverrideManager:
    return OverrideManager(jsonl_writer)


class TestOverrideManager:
    def test_create_override_records_to_jsonl(
        self, manager: OverrideManager, jsonl_writer: JsonlWriter
    ) -> None:
        record = manager.create_override(
            product="payment-api",
            tier="critical",
            failed_scanners=["semgrep"],
            reason="scanner_timeout",
            justification="Semgrep server unreachable during deploy window",
            approver="force-override",
        )
        assert record is not None

        lines = jsonl_writer.output_path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["type"] == "override"
        assert entry["data"]["product"] == "payment-api"
        assert entry["data"]["id"] == record.id

    def test_override_id_format(self, manager: OverrideManager) -> None:
        record = manager.create_override(
            product="payment-api",
            tier="high",
            failed_scanners=["grype"],
            reason="scanner_service_down",
            justification="Grype DB mirror down",
        )
        assert re.match(r"^OVR-\d{4}-\d{4}-\d{3}$", record.id)

    def test_invalid_reason_raises(self, manager: OverrideManager) -> None:
        with pytest.raises(ValueError, match="Invalid override reason"):
            manager.create_override(
                product="payment-api",
                tier="critical",
                failed_scanners=["semgrep"],
                reason="i_just_want_to_deploy",
                justification="YOLO",
            )

    def test_override_has_sla_deadline(self, manager: OverrideManager) -> None:
        record = manager.create_override(
            product="payment-api",
            tier="critical",
            failed_scanners=["semgrep"],
            reason="emergency_hotfix",
            justification="P0 incident",
            sla_hours=4,
        )
        ts = datetime.fromisoformat(record.timestamp)
        sla = datetime.fromisoformat(record.deferred_scan_sla)
        diff_hours = (sla - ts).total_seconds() / 3600
        assert diff_hours == pytest.approx(4.0)

    def test_get_pending_overrides(
        self, manager: OverrideManager, jsonl_writer: JsonlWriter
    ) -> None:
        manager.create_override(
            product="payment-api",
            tier="critical",
            failed_scanners=["semgrep"],
            reason="scanner_timeout",
            justification="timeout",
        )
        manager.create_override(
            product="billing-api",
            tier="high",
            failed_scanners=["grype"],
            reason="scanner_service_down",
            justification="down",
        )

        all_pending = manager.get_pending_overrides()
        assert len(all_pending) == 2

        filtered = manager.get_pending_overrides(product="payment-api")
        assert len(filtered) == 1
        assert filtered[0].product == "payment-api"

    def test_override_record_contains_all_fields(self, manager: OverrideManager) -> None:
        record = manager.create_override(
            product="payment-api",
            tier="critical",
            failed_scanners=["semgrep", "grype"],
            reason="emergency_hotfix",
            justification="P0 production incident requires immediate deploy",
            approver="force-override",
            sla_hours=4,
        )
        assert isinstance(record, OverrideRecord)
        assert record.product == "payment-api"
        assert record.tier == "critical"
        assert record.failed_scanners == ["semgrep", "grype"]
        assert record.reason == "emergency_hotfix"
        assert record.justification == "P0 production incident requires immediate deploy"
        assert record.approver == "force-override"
        assert record.timestamp != ""
        assert record.deferred_scan_sla != ""
        assert record.id.startswith("OVR-")
