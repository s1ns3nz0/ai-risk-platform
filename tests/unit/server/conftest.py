"""Fixtures for server tests — bootstraps a ServerState pointing at the
repo's bundled controls and the examples/ product directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator.server.app import create_app
from orchestrator.server.state import ServerState

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def server_state(tmp_path: Path) -> ServerState:
    state = ServerState(
        controls_dir=_REPO_ROOT / "controls" / "baselines",
        tier_mappings_path=_REPO_ROOT / "controls" / "tier-mappings.yaml",
        products_dir=_REPO_ROOT / "examples",
        rego_dir=_REPO_ROOT / "rego" / "gates",
        scan_roots=[tmp_path],
        # Isolate persisted assessments under tmp_path so tests don't write
        # into the bundled examples/ directory.
        assessments_dir=tmp_path / "assessments",
    )
    state.load()
    return state


@pytest.fixture
def client(server_state: ServerState) -> TestClient:
    app = create_app(server_state, api_key=None)
    return TestClient(app)


@pytest.fixture
def authed_client(server_state: ServerState) -> tuple[TestClient, dict[str, str]]:
    app = create_app(server_state, api_key="test-secret")
    return TestClient(app), {"X-API-Key": "test-secret"}


@pytest.fixture
def semgrep_payload() -> dict:
    return {
        "trigger": "pre_merge",
        "async_mode": False,
        "results": [
            {
                "scanner": "semgrep",
                "content": {
                    "results": [
                        {
                            "check_id": "python.lang.security.dangerous-system-call",
                            "path": "app/server.py",
                            "start": {"line": 42},
                            "extra": {"severity": "ERROR", "message": "os.system with user input"},
                        }
                    ],
                    "errors": [],
                },
            },
            {
                "scanner": "gitleaks",
                "content": [
                    {"RuleID": "aws-access-key", "File": "app/keys.py", "StartLine": 3, "Description": "AWS key"}
                ],
            },
        ],
    }
