"""scan-assess target_path is constrained to the configured roots."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchestrator.server.app import create_app
from orchestrator.server.state import ServerState

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _make_state(scan_roots):
    state = ServerState(
        controls_dir=_REPO_ROOT / "controls" / "baselines",
        tier_mappings_path=_REPO_ROOT / "controls" / "tier-mappings.yaml",
        products_dir=_REPO_ROOT / "examples",
        rego_dir=_REPO_ROOT / "rego" / "gates",
        scan_roots=scan_roots,
    )
    state.load()
    return state


def test_scan_mode_disabled_when_no_roots():
    state = _make_state([])
    client = TestClient(create_app(state, api_key=None))
    r = client.post(
        "/v1/products/payment-api/scan-assess",
        json={"target_path": "/tmp", "trigger": "pre_merge"},
    )
    assert r.status_code == 403
    assert "scan-mode disabled" in r.json()["detail"]


def test_rejects_path_outside_allowlist(tmp_path):
    state = _make_state([tmp_path])
    client = TestClient(create_app(state, api_key=None))
    r = client.post(
        "/v1/products/payment-api/scan-assess",
        json={"target_path": "/etc", "trigger": "pre_merge"},
    )
    assert r.status_code == 403


def test_rejects_traversal_outside_root(tmp_path):
    """`tmp_path/../somewhere-else` must not escape the root."""
    state = _make_state([tmp_path])
    outside = tmp_path.parent / "elsewhere"
    outside.mkdir(exist_ok=True)
    client = TestClient(create_app(state, api_key=None))
    r = client.post(
        "/v1/products/payment-api/scan-assess",
        json={"target_path": str(outside), "trigger": "pre_merge"},
    )
    assert r.status_code == 403


def test_rejects_nonexistent_path(tmp_path):
    state = _make_state([tmp_path])
    client = TestClient(create_app(state, api_key=None))
    r = client.post(
        "/v1/products/payment-api/scan-assess",
        json={"target_path": str(tmp_path / "missing"), "trigger": "pre_merge"},
    )
    assert r.status_code == 403
