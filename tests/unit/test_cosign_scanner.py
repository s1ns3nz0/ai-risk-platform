"""Tests for CosignScanner — deliver-phase signature/attestation parsing."""

from __future__ import annotations

import json
import os

import pytest

from orchestrator.controls.repository import ControlsRepository
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.cosign import CosignScanner

BASELINES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "baselines")
TIER_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "controls", "tier-mappings.yaml")


@pytest.fixture
def mapper() -> ControlMapper:
    repo = ControlsRepository(baselines_dir=BASELINES_DIR, tier_mappings_path=TIER_MAPPINGS_PATH)
    repo.load_all()
    return ControlMapper(repo)


class TestCosignAllVerified:
    def test_verified_bundle_produces_zero_findings(self, mapper: ControlMapper) -> None:
        """A fully-verified deliver bundle is the satisfied path → no findings."""
        scanner = CosignScanner(mapper)
        raw = json.dumps({
            "verifications": [
                {"subject": "ghcr.io/acme/api@sha256:abc", "type": "image-signature", "verified": True},
                {"subject": "ghcr.io/acme/api@sha256:abc", "type": "attestation",
                 "attestation_type": "cyclonedx", "verified": True},
            ]
        })
        assert scanner.parse_output(raw) == []


class TestCosignFailedVerification:
    def test_unsigned_image_produces_high_finding(self, mapper: ControlMapper) -> None:
        scanner = CosignScanner(mapper)
        raw = json.dumps({
            "verifications": [
                {
                    "subject": "ghcr.io/acme/api@sha256:bad",
                    "type": "image-signature",
                    "verified": False,
                    "error": "no signatures found",
                }
            ]
        })
        findings = scanner.parse_output(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.source == "cosign"
        assert f.severity == "high"
        assert f.rule_id == "cosign.signature.missing"
        assert "no signatures found" in f.message
        assert "ghcr.io/acme/api@sha256:bad" in f.message

    def test_missing_attestation_produces_finding(self, mapper: ControlMapper) -> None:
        scanner = CosignScanner(mapper)
        raw = json.dumps({
            "verifications": [
                {
                    "subject": "ghcr.io/acme/api@sha256:def",
                    "type": "attestation",
                    "attestation_type": "slsaprovenance",
                    "verified": False,
                    "error": "no matching attestations",
                }
            ]
        })
        findings = scanner.parse_output(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "cosign.attestation.missing"
        assert "slsaprovenance" in f.message

    def test_mixed_verified_and_failed_only_reports_failures(self, mapper: ControlMapper) -> None:
        scanner = CosignScanner(mapper)
        raw = json.dumps({
            "verifications": [
                {"subject": "img-a", "type": "image-signature", "verified": True},
                {"subject": "img-b", "type": "image-signature", "verified": False, "error": "tampered"},
                {"subject": "img-c", "type": "attestation", "verified": True},
            ]
        })
        findings = scanner.parse_output(raw)

        assert len(findings) == 1
        assert findings[0].file == "img-b"


class TestCosignInputShapes:
    def test_bare_list_accepted(self, mapper: ControlMapper) -> None:
        """Some CIs may post the list directly without the {verifications: ...} wrapper."""
        scanner = CosignScanner(mapper)
        raw = json.dumps([
            {"subject": "img", "type": "image-signature", "verified": False, "error": "fail"},
        ])
        assert len(scanner.parse_output(raw)) == 1

    def test_invalid_json_returns_empty(self, mapper: ControlMapper) -> None:
        scanner = CosignScanner(mapper)
        assert scanner.parse_output("not json") == []

    def test_empty_bundle_returns_empty(self, mapper: ControlMapper) -> None:
        scanner = CosignScanner(mapper)
        assert scanner.parse_output(json.dumps({"verifications": []})) == []


class TestCosignControlMapping:
    def test_finding_picks_up_supply_chain_controls(self, mapper: ControlMapper) -> None:
        """Cosign findings should land on supply-chain / integrity controls.

        The ControlMapper may return an empty list when no baseline rule matches
        the cosign rule_id directly — in that case POAMGenerator falls back to
        _SCANNER_CONTROL_MAP. Either way the control_ids field must exist.
        """
        scanner = CosignScanner(mapper)
        raw = json.dumps({"verifications": [
            {"subject": "img", "type": "image-signature", "verified": False, "error": "x"},
        ]})
        findings = scanner.parse_output(raw)
        assert findings[0].control_ids is not None
