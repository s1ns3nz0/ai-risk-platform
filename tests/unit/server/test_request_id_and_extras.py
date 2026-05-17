"""Request IDs, payload validation, Bedrock sync-mode rejection."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from orchestrator.server.app import create_app


def test_request_id_returned_in_header(client):
    r = client.get("/v1/products")
    assert r.status_code == 200
    assert r.headers.get("X-Request-Id")


def test_request_id_honors_caller(client):
    r = client.get("/v1/products", headers={"X-Request-Id": "my-trace-123"})
    assert r.headers["X-Request-Id"] == "my-trace-123"


def test_invalid_scanner_name_rejected(client):
    bad = {
        "results": [{"scanner": "made-up-scanner", "content": {"results": [], "errors": []}}]
    }
    r = client.post("/v1/products/payment-api/assess", json=bad)
    assert r.status_code == 422


def test_non_container_content_rejected(client):
    bad = {"results": [{"scanner": "semgrep", "content": "not-an-object"}]}
    r = client.post("/v1/products/payment-api/assess", json=bad)
    assert r.status_code == 422


def test_bedrock_mode_rejects_sync(server_state, semgrep_payload):
    """When clients.mode is bedrock, sync requests must be refused."""
    server_state.clients.mode = "bedrock"
    app = create_app(server_state, api_key=None)
    client = TestClient(app)
    r = client.post("/v1/products/payment-api/assess", json=semgrep_payload)
    assert r.status_code == 400
    assert "async" in r.json()["detail"]


def test_cors_off_by_default(client):
    r = client.options(
        "/v1/products",
        headers={"Origin": "https://dash.example.com", "Access-Control-Request-Method": "GET"},
    )
    # Without CORS middleware, the OPTIONS response carries no allow-origin.
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_cors_when_configured(server_state):
    app = create_app(server_state, api_key=None, cors_origins=["https://dash.example.com"])
    client = TestClient(app)
    r = client.get("/v1/products", headers={"Origin": "https://dash.example.com"})
    assert r.headers.get("access-control-allow-origin") == "https://dash.example.com"
