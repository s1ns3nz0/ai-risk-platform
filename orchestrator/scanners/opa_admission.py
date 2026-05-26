"""OPA admission-policy result adapter — deliver-phase configuration gates.

This scanner does NOT execute Gatekeeper / Kyverno. The CI pipeline (or a
post-deploy job) collects admission violations from the cluster and POSTs
a normalized bundle to the platform. The platform converts the bundle into
Finding[] so the SAR can mark deliver-time configuration controls as
satisfied when zero violations are reported.

Expected input shape (CI POSTs this as `scanner: opa-admission`, `content: <dict>`):

    {
      "violations": [
        {
          "policy": "<constraint-or-policy-name>",  # e.g. "K8sRequireImageSignature"
          "engine": "gatekeeper" | "kyverno" | "kyverno-policyreport",
          "severity": "critical" | "high" | "medium" | "low",  # optional
          "resource": "Deployment/payment-api",                # optional
          "namespace": "prod",                                  # optional
          "message": "image does not have a verified signature",
          "rule_id": "..."                                       # optional override
        },
        ...
      ]
    }

Zero violations → no Finding (control satisfied).
Each violation → one Finding tagged with the policy id.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


# Default severity when the admission engine doesn't tag one. Admission
# violations block deploy by definition, so they're never low-severity.
_DEFAULT_SEVERITY = "high"

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}


class OpaAdmissionScanner:
    """Parser for OPA Gatekeeper / Kyverno admission violation bundles."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "opa-admission"

    def parse_output(self, raw_output: str) -> list[Finding]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("opa-admission payload is not valid JSON")
            return []

        violations = self._extract_violations(data)
        findings: list[Finding] = []

        for entry in violations:
            if not isinstance(entry, dict):
                continue

            policy = str(entry.get("policy") or entry.get("rule_id") or "")
            rule_id = str(entry.get("rule_id") or policy or "opa.policy.violation")
            severity = str(entry.get("severity") or _DEFAULT_SEVERITY).lower()
            if severity not in _ALLOWED_SEVERITIES:
                severity = _DEFAULT_SEVERITY

            resource = str(entry.get("resource") or "")
            namespace = str(entry.get("namespace") or "")
            engine = str(entry.get("engine") or "opa")
            raw_message = str(entry.get("message") or "admission policy violation")

            file_ref = f"{namespace}/{resource}" if namespace and resource else (resource or namespace)
            message = f"{engine}: {raw_message}" if engine else raw_message
            if policy and policy not in message:
                message = f"[{policy}] {message}"

            findings.append(
                Finding(
                    source="opa-admission",
                    rule_id=rule_id,
                    severity=severity,
                    file=file_ref,
                    line=0,
                    message=message,
                    control_ids=self._control_mapper.map_finding("opa-admission", rule_id),
                    product="",
                )
            )

        return findings

    @staticmethod
    def _extract_violations(data: Any) -> list[dict[str, Any]]:
        """Accept {'violations': [...]} (preferred) or a bare list."""
        if isinstance(data, dict):
            violations = data.get("violations")
            if isinstance(violations, list):
                return violations
            return []
        if isinstance(data, list):
            return data
        return []
