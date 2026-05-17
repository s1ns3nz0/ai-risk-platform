"""Import-mode assess: sync + async flows."""

from __future__ import annotations

import time


def test_sync_assessment_returns_full_report(client, semgrep_payload):
    r = client.post("/v1/products/payment-api/assess", json=semgrep_payload)
    assert r.status_code == 200
    body = r.json()
    assert body["product"] == "payment-api"
    assert body["tier"] in ("critical", "high")
    assert body["findings_count"] >= 2
    assert body["mode"] == "static"
    # Gate should block on the critical secret.
    assert body["gate"]["passed"] is False


def test_no_findings_returns_400(client):
    empty = {
        "results": [
            {"scanner": "semgrep", "content": {"results": [], "errors": []}}
        ]
    }
    r = client.post("/v1/products/payment-api/assess", json=empty)
    assert r.status_code == 400


def test_unknown_product_returns_404(client, semgrep_payload):
    r = client.post("/v1/products/does-not-exist/assess", json=semgrep_payload)
    assert r.status_code == 404


def test_async_assessment_completes(client, semgrep_payload):
    semgrep_payload["async_mode"] = True
    r = client.post("/v1/products/payment-api/assess", json=semgrep_payload)
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        s = client.get(f"/v1/jobs/{job_id}").json()
        if s["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert s["status"] == "completed"
    assert s["result"]["product"] == "payment-api"


def test_results_array_max_length_enforced(client):
    payload = {
        "results": [
            {"scanner": "semgrep", "content": {"results": [], "errors": []}}
            for _ in range(65)
        ]
    }
    r = client.post("/v1/products/payment-api/assess", json=payload)
    # Pydantic 422 for max_length violation.
    assert r.status_code == 422
