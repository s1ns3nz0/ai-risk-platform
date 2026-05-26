"""Cosign (Sigstore) verification adapter — deliver-phase signature checks.

This scanner does NOT execute cosign. The CI pipeline runs `cosign verify`
and `cosign verify-attestation` itself, then POSTs a normalized result
bundle to the platform. The platform converts the bundle into Finding[]
so the SAR can mark deliver-time integrity controls as satisfied.

Expected input shape (CI POSTs this as `scanner: cosign`, `content: <dict>`):

    {
      "verifications": [
        {
          "subject": "<image-or-artifact-ref>",  # e.g. "ghcr.io/acme/api@sha256:..."
          "type": "image-signature" | "attestation",
          "attestation_type": "cyclonedx" | "slsaprovenance" | "spdx" | "...",
          "verified": true | false,
          "issuer": "https://accounts.google.com" | "https://token.actions.githubusercontent.com",
          "subject_identity": "...",
          "digest": "sha256:...",
          "error": "no signatures found" | "..."   # only when verified=false
        },
        ...
      ]
    }

`verified: true`  → no Finding (control satisfied)
`verified: false` → high-severity Finding tagged with the cosign rule id
                    derived from verification type (signature vs attestation).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


# Map cosign verification kind → stable rule id. Mirrors the convention used
# by SAST/SCA scanners (semgrep rule id, CVE id) so the control mapper and
# POA&M deduper treat each failure type as a stable threat event key.
_RULE_ID = {
    "image-signature": "cosign.signature.missing",
    "attestation":     "cosign.attestation.missing",
}

_RULE_ID_FALLBACK = "cosign.verification.failed"


class CosignScanner:
    """Parser for cosign verify / verify-attestation result bundles."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "cosign"

    def parse_output(self, raw_output: str) -> list[Finding]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("cosign payload is not valid JSON")
            return []

        verifications = self._extract_verifications(data)
        findings: list[Finding] = []

        for entry in verifications:
            if not isinstance(entry, dict):
                continue
            if entry.get("verified") is True:
                # Successful verification → control satisfied (no finding).
                continue

            kind = str(entry.get("type") or "").lower()
            rule_id = _RULE_ID.get(kind, _RULE_ID_FALLBACK)
            subject = str(entry.get("subject") or entry.get("digest") or "")
            attestation_type = str(entry.get("attestation_type") or "")
            error = str(entry.get("error") or "unverified")

            message_bits = [f"cosign verification failed for {subject or 'unknown subject'}"]
            if attestation_type:
                message_bits.append(f"(attestation type: {attestation_type})")
            message_bits.append(f"— {error}")
            message = " ".join(message_bits)

            findings.append(
                Finding(
                    source="cosign",
                    rule_id=rule_id,
                    severity="high",
                    file=subject,
                    line=0,
                    message=message,
                    control_ids=self._control_mapper.map_finding("cosign", rule_id),
                    product="",
                )
            )

        return findings

    @staticmethod
    def _extract_verifications(data: Any) -> list[dict[str, Any]]:
        """Accept either {'verifications': [...]} (preferred) or a bare list."""
        if isinstance(data, dict):
            verifications = data.get("verifications")
            if isinstance(verifications, list):
                return verifications
            return []
        if isinstance(data, list):
            return data
        return []
