"""Body-size middleware rejects oversize requests via Content-Length."""

from __future__ import annotations

from fastapi.testclient import TestClient

from orchestrator.server.app import create_app


def test_oversize_content_length_returns_413(server_state):
    app = create_app(server_state, api_key=None, max_body_bytes=1024)
    client = TestClient(app)
    big_payload = {"results": [{"scanner": "semgrep", "content": {"results": [], "errors": []}}]}
    # Spoof an oversize Content-Length header.
    r = client.post(
        "/v1/products/payment-api/assess",
        json=big_payload,
        headers={"Content-Length": "999999"},
    )
    assert r.status_code == 413
