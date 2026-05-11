"""Tests for Rego policy files — syntax validation and OPA integration."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REGO_DIR = Path(__file__).resolve().parents[2] / "rego" / "gates"

EXPECTED_FILES = [
    "pci_critical_findings.rego",
    "secrets_detection.rego",
    "high_severity_threshold.rego",
    "iac_network_segmentation.rego",
]

opa_installed = shutil.which("opa") is not None


# --- Syntax / structural tests (no OPA required) ---


class TestRegoFilesExist:
    def test_rego_files_exist(self) -> None:
        """rego/gates/ contains all 4 expected .rego files."""
        for name in EXPECTED_FILES:
            assert (REGO_DIR / name).is_file(), f"Missing: {name}"


class TestRegoPackageGates:
    def test_rego_files_have_package_gates(self) -> None:
        """Every .rego file declares 'package gates'."""
        for name in EXPECTED_FILES:
            text = (REGO_DIR / name).read_text()
            assert "package gates" in text, f"{name} missing 'package gates'"


class TestRegoDenyRule:
    def test_rego_files_have_deny_rule(self) -> None:
        """Every .rego file contains a 'deny[msg]' rule."""
        pattern = re.compile(r"deny\[msg\]")
        for name in EXPECTED_FILES:
            text = (REGO_DIR / name).read_text()
            assert pattern.search(text), f"{name} missing 'deny[msg]' rule"


# --- OPA integration tests (skipped when OPA CLI not installed) ---


def _opa_eval(input_data: dict) -> list[str]:
    """Run OPA eval and return deny messages."""
    result = subprocess.run(
        [
            "opa", "eval",
            "-i", "/dev/stdin",
            "-d", str(REGO_DIR),
            "-f", "json",
            "data.gates.deny",
        ],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"OPA failed: {result.stderr}"
    output = json.loads(result.stdout)
    messages: list[str] = []
    for r in output.get("result", []):
        for expr in r.get("expressions", []):
            value = expr.get("value", [])
            if isinstance(value, list):
                messages.extend(str(v) for v in value)
    return messages


@pytest.mark.skipif(not opa_installed, reason="OPA CLI not installed")
class TestPciCriticalBlocks:
    def test_pci_critical_blocks(self) -> None:
        """Critical PCI finding in critical tier -> deny."""
        input_data = {
            "findings": [
                {
                    "source": "semgrep",
                    "rule_id": "sql-injection",
                    "severity": "critical",
                    "file": "app.py",
                    "line": 10,
                    "message": "SQL injection",
                    "control_ids": ["PCI-DSS-6.3.1"],
                    "product": "payment-api",
                },
            ],
            "context": {
                "tier": "critical",
                "findings_count": {"critical": 1, "high": 0},
                "secrets_count": 0,
            },
        }
        messages = _opa_eval(input_data)
        assert len(messages) > 0
        assert any("Critical finding in PCI scope" in m for m in messages)


@pytest.mark.skipif(not opa_installed, reason="OPA CLI not installed")
class TestSecretsBlocks:
    def test_secrets_blocks(self) -> None:
        """Secrets detected -> deny."""
        input_data = {
            "findings": [],
            "context": {
                "tier": "low",
                "findings_count": {"critical": 0, "high": 0},
                "secrets_count": 3,
            },
        }
        messages = _opa_eval(input_data)
        assert len(messages) > 0
        assert any("Secrets detected" in m for m in messages)


@pytest.mark.skipif(not opa_installed, reason="OPA CLI not installed")
class TestCleanPasses:
    def test_clean_passes(self) -> None:
        """No findings, no secrets -> empty deny set."""
        input_data = {
            "findings": [],
            "context": {
                "tier": "low",
                "findings_count": {"critical": 0, "high": 0},
                "secrets_count": 0,
            },
        }
        messages = _opa_eval(input_data)
        assert messages == []
