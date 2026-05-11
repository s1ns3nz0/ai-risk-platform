"""OPA/Rego policy evaluator.

Two additive layers (ADR-003, ADR-004):
1. YAML thresholds (fast path) — ThresholdEvaluator handles this
2. Rego policies (detailed path) — this class handles this
Both must pass for gate to open.

Rules:
- 100% local (ADR-003). OPA CLI via subprocess.
- AI never gates (ADR-004).
- Rego files loaded from policies_dir (typically rego/gates/).
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from orchestrator.types import Finding, GateDecision

logger = logging.getLogger(__name__)


class OpaEvaluator:
    """OPA/Rego policy evaluator — additive layer on top of YAML thresholds."""

    def __init__(self, policies_dir: str) -> None:
        self._policies_dir = Path(policies_dir)

    def evaluate(self, findings: list[Finding], context: dict[str, object]) -> GateDecision:
        """Evaluate findings against all .rego policies in policies_dir.

        Returns PASS if:
        - No .rego files exist (nothing to evaluate)
        - OPA CLI is not installed (graceful skip)
        - OPA returns empty deny set

        Returns FAIL if OPA deny set is non-empty.
        """
        rego_files = list(self._policies_dir.glob("*.rego"))
        if not rego_files:
            return GateDecision(
                passed=True,
                reason="opa: no rego policies found, skipping",
                threshold_results=[],
                findings_count={},
            )

        input_data = self._build_input(findings, context)

        try:
            deny_messages = self._run_opa(input_data)
        except FileNotFoundError:
            logger.warning("OPA CLI not installed — skipping Rego evaluation. YAML thresholds still apply.")
            return GateDecision(
                passed=True,
                reason="opa: CLI not installed, skipped (YAML thresholds still apply)",
                threshold_results=[],
                findings_count={},
            )

        if not deny_messages:
            return GateDecision(
                passed=True,
                reason="opa: all policies passed",
                threshold_results=[],
                findings_count={},
            )

        return GateDecision(
            passed=False,
            reason="; ".join(deny_messages),
            threshold_results=[],
            findings_count={},
        )

    def _build_input(self, findings: list[Finding], context: dict[str, object]) -> dict[str, object]:
        """Build OPA input JSON from findings and context."""
        return {
            "findings": [
                {
                    "source": f.source,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "file": f.file,
                    "line": f.line,
                    "message": f.message,
                    "control_ids": f.control_ids,
                    "product": f.product,
                }
                for f in findings
            ],
            "context": context,
        }

    def _run_opa(self, input_data: dict[str, object]) -> list[str]:
        """Execute OPA CLI and return deny messages.

        Raises FileNotFoundError if OPA is not installed.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(input_data, f)
            input_path = f.name

        try:
            result = subprocess.run(
                [
                    "opa", "eval",
                    "-i", input_path,
                    "-d", str(self._policies_dir),
                    "-f", "json",
                    "data.gates.deny",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            Path(input_path).unlink(missing_ok=True)

        if result.returncode != 0:
            error_msg = f"OPA evaluation error (exit {result.returncode}) — policy enforcement unavailable: {result.stderr[:200]}"
            logger.error(error_msg)
            return [error_msg]  # Fail-closed: broken OPA = deny

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            error_msg = f"OPA returned invalid JSON — policy enforcement unavailable: {result.stdout[:100]}"
            logger.error(error_msg)
            return [error_msg]  # Fail-closed: garbled output = deny

        # Extract deny messages from OPA output
        deny_messages: list[str] = []
        for r in output.get("result", []):
            for expr in r.get("expressions", []):
                value = expr.get("value", [])
                if isinstance(value, list):
                    deny_messages.extend(str(v) for v in value)
                elif isinstance(value, set):
                    deny_messages.extend(str(v) for v in value)

        return deny_messages
