"""Tests for the file-based AssessmentStore."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestrator.persistence import AssessmentRecord, AssessmentStore


def test_save_and_get_round_trip(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    rec = AssessmentRecord(
        id="RA-20260517-deadbeef",
        product="payment-api",
        created_at="2026-05-17T12:00:00+00:00",
        payload={"poam": {"items": []}, "tier": "high"},
    )
    store.save(rec)
    got = store.get("payment-api", "RA-20260517-deadbeef")
    assert got is not None
    assert got.id == rec.id
    assert got.payload["tier"] == "high"


def test_list_for_product_returns_summaries_newest_first(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    for i in range(3):
        store.save(AssessmentRecord(
            id=f"RA-2026051{i}-aaaa",
            product="payment-api",
            created_at=f"2026-05-1{i}T00:00:00+00:00",
            payload={},
        ))
    items = store.list_for_product("payment-api")
    assert len(items) == 3
    # newest first by created_at
    assert items[0]["created_at"] > items[1]["created_at"] > items[2]["created_at"]


def test_unknown_assessment_returns_none(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    assert store.get("payment-api", "RA-not-there") is None


def test_update_poam_section_merges_into_named_item(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    store.save(AssessmentRecord(
        id="RA-X",
        product="p",
        created_at="2026-05-17T00:00:00+00:00",
        payload={"poam": {"items": [
            {"id": "POAM-1", "ticket": {"id": "", "url": ""}},
            {"id": "POAM-2", "ticket": {"id": "", "url": ""}},
        ]}},
    ))
    rec = store.update_poam_section(
        product="p", assessment_id="RA-X", poam_id="POAM-2",
        section="ticket", values={"id": "SEC-202605-001", "url": "https://example/1"},
    )
    assert rec is not None
    items = rec.payload["poam"]["items"]
    assert items[1]["ticket"]["id"] == "SEC-202605-001"
    # Other items untouched.
    assert items[0]["ticket"]["id"] == ""


def test_update_section_unknown_returns_none(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    store.save(AssessmentRecord(
        id="RA-X", product="p", created_at="t",
        payload={"poam": {"items": [{"id": "POAM-1"}]}},
    ))
    assert store.update_poam_section("p", "RA-X", "POAM-NOPE", "ticket", {"id": "x"}) is None
    assert store.update_poam_section("p", "RA-MISSING", "POAM-1", "ticket", {"id": "x"}) is None


def test_invalid_section_raises(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    store.save(AssessmentRecord(
        id="RA-X", product="p", created_at="t",
        payload={"poam": {"items": [{"id": "POAM-1"}]}},
    ))
    with pytest.raises(ValueError):
        store.update_poam_section("p", "RA-X", "POAM-1", "free_form_section", {"x": 1})


def test_verification_section_auto_stamps_timestamp(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    store.save(AssessmentRecord(
        id="RA-V", product="p", created_at="t",
        payload={"poam": {"items": [{"id": "POAM-1", "verification": {}}]}},
    ))
    rec = store.update_poam_section(
        "p", "RA-V", "POAM-1", "verification", {"verified_by": "alice"},
    )
    item = rec.payload["poam"]["items"][0]
    assert item["verification"]["verified_by"] == "alice"
    # auto-stamped timestamp is non-empty ISO format
    assert "T" in item["verification"]["verified_at"]


def test_new_id_has_expected_shape(tmp_path: Path):
    store = AssessmentStore(tmp_path)
    aid = store.new_id()
    assert aid.startswith("RA-")
    # RA-YYYYMMDD-<8 hex>
    parts = aid.split("-")
    assert len(parts) == 3 and len(parts[1]) == 8 and len(parts[2]) == 8
