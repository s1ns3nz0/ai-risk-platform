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


def test_zero_findings_is_a_clean_scan_not_an_error(client):
    """A successful scan that produced zero findings is a valid assessment
    outcome (low risk). The endpoint must NOT 400 on this — that would
    force every CI to special-case clean runs."""
    empty = {
        "results": [
            {"scanner": "semgrep", "content": {"results": [], "errors": []}}
        ]
    }
    r = client.post("/v1/products/payment-api/assess", json=empty)
    assert r.status_code == 200
    body = r.json()
    assert body["findings_count"] == 0
    # Clean scan → gate passes.
    assert body["gate"]["passed"] is True


def test_authorization_decision_is_binary_ato_or_dato(client, semgrep_payload):
    """The /assess endpoint must only ever report decision=ATO or =DATO.
    `ATO-with-conditions` was retired because CI/CD needs strict binary."""
    # Blocking case (semgrep_payload has a critical finding).
    r = client.post("/v1/products/payment-api/assess", json=semgrep_payload)
    assert r.status_code == 200
    auth = r.json()["authorization"]
    assert auth["decision"] in {"ATO", "DATO"}

    # Clean case.
    clean = {"results": [{"scanner": "semgrep", "content": {"results": [], "errors": []}}]}
    r2 = client.post("/v1/products/payment-api/assess", json=clean)
    auth2 = r2.json()["authorization"]
    assert auth2["decision"] in {"ATO", "DATO"}


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
