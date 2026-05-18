"""GET + POA&M-update endpoints over the persisted store."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator.server.app import create_app
from orchestrator.server.state import ServerState

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def isolated_state(tmp_path: Path) -> ServerState:
    """State with assessments_dir under tmp_path so tests don't pollute
    the bundled examples directory."""
    state = ServerState(
        controls_dir=_REPO_ROOT / "controls" / "baselines",
        tier_mappings_path=_REPO_ROOT / "controls" / "tier-mappings.yaml",
        products_dir=_REPO_ROOT / "examples",
        rego_dir=_REPO_ROOT / "rego" / "gates",
        scan_roots=[tmp_path],
        assessments_dir=tmp_path / "assessments",
    )
    state.load()
    return state


@pytest.fixture
def iso_client(isolated_state: ServerState) -> TestClient:
    return TestClient(create_app(isolated_state, api_key=None))


def _post_and_get_aid(client: TestClient) -> str:
    payload = {
        "results": [{
            "scanner": "semgrep",
            "content": {
                "results": [{
                    "check_id": "x", "path": "a.py", "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": "m"},
                }],
                "errors": [],
            },
        }],
        "evidence_url": "https://gha/runs/1",
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    assert r.status_code == 200, r.text
    return r.json()["assessment_id"]


# ---------------- persistence ----------------


def test_assessment_persisted_and_id_returned(iso_client):
    aid = _post_and_get_aid(iso_client)
    assert aid.startswith("RA-")

    # The new GET endpoint returns the stored record.
    r = iso_client.get(f"/v1/products/payment-api/assessments/{aid}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == aid
    assert body["product"] == "payment-api"
    assert body["payload"]["findings_count"] >= 1


def test_list_returns_summaries(iso_client):
    aids = [_post_and_get_aid(iso_client) for _ in range(2)]
    r = iso_client.get("/v1/products/payment-api/assessments")
    assert r.status_code == 200
    listed = r.json()["assessments"]
    assert {a["id"] for a in listed} >= set(aids)
    for entry in listed:
        # summary only, no big payload
        assert set(entry.keys()) == {"id", "product", "created_at"}


def test_get_unknown_assessment_returns_404(iso_client):
    r = iso_client.get("/v1/products/payment-api/assessments/RA-NOT-EXIST")
    assert r.status_code == 404


def test_list_for_unknown_product_returns_404(iso_client):
    r = iso_client.get("/v1/products/does-not-exist/assessments")
    assert r.status_code == 404


# ---------------- by-phase grouping ----------------


def test_by_phase_groups_pre_merge_findings_under_build(iso_client):
    aid = _post_and_get_aid(iso_client)  # default trigger=pre_merge
    r = iso_client.get(f"/v1/products/payment-api/assessments/{aid}/by-phase")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["assessment_id"] == aid
    assert set(body["by_phase"].keys()) >= {"BUILD", "TEST", "DEPLOY", "OPERATE"}
    assert body["counts"]["BUILD"] >= 1
    assert body["counts"]["DEPLOY"] == 0
    assert body["counts"]["OPERATE"] == 0
    # Every grouped item carries the matching source_detail.phase.
    for item in body["by_phase"]["BUILD"]:
        assert item["source_detail"]["phase"] == "BUILD"


def test_by_phase_pre_deploy_lands_in_deploy(iso_client):
    payload = {
        "trigger": "pre_deploy",
        "results": [{
            "scanner": "semgrep",
            "content": {
                "results": [{
                    "check_id": "x", "path": "a.py", "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": "m"},
                }],
                "errors": [],
            },
        }],
    }
    aid = iso_client.post("/v1/products/payment-api/assess", json=payload).json()["assessment_id"]
    body = iso_client.get(f"/v1/products/payment-api/assessments/{aid}/by-phase").json()
    assert body["counts"]["DEPLOY"] >= 1
    assert body["counts"]["BUILD"] == 0


def test_by_phase_unknown_assessment_returns_404(iso_client):
    r = iso_client.get("/v1/products/payment-api/assessments/RA-NOPE/by-phase")
    assert r.status_code == 404


# ---------------- POA&M update endpoints ----------------


def _first_poam_id(iso_client: TestClient, aid: str) -> str:
    body = iso_client.get(f"/v1/products/payment-api/assessments/{aid}").json()
    items = body["payload"]["poam"]["items"]
    assert items, "expected at least one POA&M item"
    return items[0]["id"]


def test_attach_ticket(iso_client):
    aid = _post_and_get_aid(iso_client)
    pid = _first_poam_id(iso_client, aid)
    r = iso_client.post(
        f"/v1/products/payment-api/assessments/{aid}/poam/{pid}/ticket",
        json={"id": "SEC-202605-001", "url": "https://github.com/org/repo/issues/1"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ticket"]["id"] == "SEC-202605-001"
    # Persisted: re-read the assessment and check the same field.
    body = iso_client.get(f"/v1/products/payment-api/assessments/{aid}").json()
    target = next(it for it in body["payload"]["poam"]["items"] if it["id"] == pid)
    assert target["ticket"]["id"] == "SEC-202605-001"


def test_attach_delay_requires_both_fields(iso_client):
    aid = _post_and_get_aid(iso_client)
    pid = _first_poam_id(iso_client, aid)
    bad = iso_client.post(
        f"/v1/products/payment-api/assessments/{aid}/poam/{pid}/delay",
        json={"justification": ""},
    )
    assert bad.status_code == 422  # missing approved_by + empty justification

    good = iso_client.post(
        f"/v1/products/payment-api/assessments/{aid}/poam/{pid}/delay",
        json={"justification": "vendor patch ETA 2026-06", "approved_by": "ciso@acme"},
    )
    assert good.status_code == 200
    assert good.json()["delay"]["approved_by"] == "ciso@acme"


def test_attach_risk_acceptance(iso_client):
    aid = _post_and_get_aid(iso_client)
    pid = _first_poam_id(iso_client, aid)
    r = iso_client.post(
        f"/v1/products/payment-api/assessments/{aid}/poam/{pid}/risk-acceptance",
        json={
            "accepted_by": "ao@acme",
            "justification": "Compensating control: WAF rule deployed",
            "compensating_controls": ["WAF-rule-42"],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()["risk_acceptance"]
    assert body["accepted_by"] == "ao@acme"
    assert body["compensating_controls"] == ["WAF-rule-42"]


def test_attach_verification_auto_stamps_time(iso_client):
    aid = _post_and_get_aid(iso_client)
    pid = _first_poam_id(iso_client, aid)
    r = iso_client.post(
        f"/v1/products/payment-api/assessments/{aid}/poam/{pid}/verification",
        json={"verified_by": "qa-bot"},  # verified_at omitted
    )
    assert r.status_code == 200
    body = r.json()["verification"]
    assert body["verified_by"] == "qa-bot"
    assert "T" in body["verified_at"]  # auto-stamped ISO timestamp


def test_update_unknown_poam_returns_404(iso_client):
    aid = _post_and_get_aid(iso_client)
    r = iso_client.post(
        f"/v1/products/payment-api/assessments/{aid}/poam/POAM-NOPE/ticket",
        json={"id": "x", "url": ""},
    )
    assert r.status_code == 404


def test_update_unknown_assessment_returns_404(iso_client):
    r = iso_client.post(
        "/v1/products/payment-api/assessments/RA-NOPE/poam/POAM-1/ticket",
        json={"id": "x", "url": ""},
    )
    assert r.status_code == 404
