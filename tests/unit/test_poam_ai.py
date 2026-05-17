"""Tests for the Bedrock POA&M enricher.

The enricher must:
- Replace static-template fields with model-generated text on success.
- Leave the static text in place when the model errors or returns garbage.
- Tolerate Bedrock-quirks: JSON wrapped in ``` fences, chatty preamble.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from orchestrator.rmf.poam import (
    POAMItem, POAMTicket, POAMWeakness, POAMSource, POAMImpact,
    POAMLifecycle, POAMRemediation, POAMDelay, POAMRiskAcceptance, POAMVerification,
)
from orchestrator.rmf.poam_ai import BedrockPOAMEnricher, _extract_json


def _item(static_desc="STATIC-DESC", static_plan="STATIC-PLAN") -> POAMItem:
    return POAMItem(
        id="POAM-2026-0517-001",
        weakness="title",
        control_id="C",
        source="grype",
        finding_id="CVE-2026-1234",
        severity="high",
        risk_level="high",
        status="open",
        milestones=[{"description": "tpl", "target_date": "+1d", "status": "open"}],
        scheduled_completion="2026-06-17",
        responsible="dev-team",
        cost_estimate="moderate",
        finding_evidence="",
        override_id="",
        ticket=POAMTicket(),
        weakness_detail=POAMWeakness(
            title="title", cve_id="CVE-2026-1234", severity="high",
            cvss_score=8.1, epss_score=0.034, package="spring-core",
            supply_chain=True, description=static_desc,
        ),
        source_detail=POAMSource(scanner="grype", scan_type="SCA", phase="BUILD",
                                framework_refs=["NIST-RA-5"], finding_id="CVE-2026-1234"),
        impact=POAMImpact(
            affected_asset="payment-api", cia={"confidentiality": "high"},
            data_classification=["PCI"], business_impact="STATIC-IMPACT",
        ),
        lifecycle=POAMLifecycle(discovered_at="t", due_date="2026-06-17", sla_days=30),
        remediation=POAMRemediation(plan=static_plan, owner="dev-team",
                                    resources_required="STATIC-RES",
                                    vendor_dependency="STATIC-VENDOR"),
        delay=POAMDelay(),
        risk_acceptance=POAMRiskAcceptance(),
        verification=POAMVerification(verified_by="automated"),
    )


def test_enricher_overwrites_static_text_on_success():
    client = MagicMock()
    client.invoke.return_value = json.dumps({
        "description": "AI-DESC: RCE in spring-core via JWT confusion.",
        "business_impact": "Could compromise payment-api auth.",
        "remediation_plan": "Upgrade to spring-core 6.1.7.",
        "resources_required": "1 engineer, 0.5 day",
        "vendor_dependency": "",
        "milestones": [
            {"description": "Patch", "target_date": "+1d"},
            {"description": "Verify", "target_date": "+15d"},
            {"description": "Deploy", "target_date": "+30d"},
        ],
    })
    items = [_item()]
    stats = BedrockPOAMEnricher(client).enrich(items)
    assert stats == {"enriched": 1, "failed": 0}
    it = items[0]
    assert it.weakness_detail.description.startswith("AI-DESC")
    assert "Upgrade" in it.remediation.plan
    assert it.impact.business_impact.startswith("Could compromise")
    assert len(it.milestones) == 3 and it.milestones[0]["description"] == "Patch"
    # vendor_dependency explicit empty → overwritten to ""
    assert it.remediation.vendor_dependency == ""


def test_enricher_fallback_preserves_static_text_on_invalid_json():
    client = MagicMock()
    client.invoke.return_value = "Sorry, I can't comply with that."
    items = [_item()]
    stats = BedrockPOAMEnricher(client).enrich(items)
    assert stats["failed"] == 1
    # Static text intact.
    assert items[0].weakness_detail.description == "STATIC-DESC"
    assert items[0].remediation.plan == "STATIC-PLAN"


def test_enricher_fallback_when_client_raises():
    client = MagicMock()
    client.invoke.side_effect = RuntimeError("bedrock down")
    items = [_item()]
    stats = BedrockPOAMEnricher(client).enrich(items)
    assert stats == {"enriched": 0, "failed": 1}
    assert items[0].weakness_detail.description == "STATIC-DESC"


def test_extract_json_handles_fenced_output():
    raw = "Here you go:\n```json\n{\"description\": \"x\"}\n```\nThanks."
    assert _extract_json(raw) == {"description": "x"}


def test_extract_json_handles_chatty_preamble():
    raw = "Sure! {\"a\": 1, \"b\": 2} hope that helps."
    assert _extract_json(raw) == {"a": 1, "b": 2}


def test_extract_json_returns_none_on_garbage():
    assert _extract_json("no json here") is None


def test_enricher_clamps_overlong_text():
    client = MagicMock()
    client.invoke.return_value = json.dumps({
        "description": "x" * 5000,
        "remediation_plan": "y" * 5000,
        "resources_required": "z" * 5000,
    })
    items = [_item()]
    BedrockPOAMEnricher(client).enrich(items)
    assert len(items[0].weakness_detail.description) == 400
    assert len(items[0].remediation.plan) == 400
    assert len(items[0].remediation.resources_required) == 200


def test_enricher_skips_empty_input():
    client = MagicMock()
    stats = BedrockPOAMEnricher(client).enrich([])
    assert stats == {"enriched": 0, "failed": 0}
    client.invoke.assert_not_called()


def test_enricher_processes_items_in_parallel():
    """Mostly a smoke test: invoke is called once per item."""
    client = MagicMock()
    client.invoke.return_value = json.dumps({"description": "ok"})
    items = [_item() for _ in range(5)]
    BedrockPOAMEnricher(client, max_workers=3).enrich(items)
    assert client.invoke.call_count == 5
