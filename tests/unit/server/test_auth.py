"""API key authentication."""

from __future__ import annotations


def test_open_when_no_api_key_configured(client):
    assert client.get("/v1/products").status_code == 200


def test_v1_routes_require_api_key_when_configured(authed_client):
    client, headers = authed_client
    assert client.get("/v1/products").status_code == 401
    assert client.get("/v1/products", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/v1/products", headers=headers).status_code == 200


def test_health_endpoints_always_open(authed_client):
    client, _ = authed_client
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_admin_reload_requires_key(authed_client):
    client, headers = authed_client
    assert client.post("/v1/admin/reload").status_code == 401
    assert client.post("/v1/admin/reload", headers=headers).status_code == 200
