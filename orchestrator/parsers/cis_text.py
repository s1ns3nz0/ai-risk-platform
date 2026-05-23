"""CIS-style plain-text parser — kube-bench / cis-java.

Both scanners emit a line-per-check format with `[PASS]`, `[FAIL]`, or
`[WARN]` prefixes. We only emit Findings for non-PASS lines: passing
checks contribute to the SAR via the submitted-scanners set (see
`/v1/products/{name}/import-assess` in `server/app.py`), not via per-line
findings — otherwise the POA&M would balloon with hundreds of "ok" rows.

Severity assignment is scanner-specific:
  * kube-bench: FAIL → high (CIS Kubernetes Benchmark hardening miss),
                WARN → medium
  * cis-java:   FAIL → medium (Java security properties; rarely
                exploitable on its own but signals config drift),
                WARN → low

NIST control fallback (also defined in rmf/poam.py for source_detail
attribution) is applied here so unmapped findings still surface against
the right control on dashboards.
"""

from __future__ import annotations

import logging
import re

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

_LINE = re.compile(r"^\s*\[(PASS|FAIL|WARN|INFO)\]\s+(\S+)\s+(.*?)\s*$")

# Scanner → (FAIL severity, WARN severity). INFO is dropped; PASS never
# generates a finding.
_SEVERITY_MAP: dict[str, tuple[str, str]] = {
    "kube-bench": ("high", "medium"),
    "cis-java":   ("medium", "low"),
}

# Fallback NIST controls when no verification_methods row in the baseline
# matches. Keeps every finding anchored to at least one control so SAR /
# POA&M tables don't show blanks.
_CONTROL_FALLBACK: dict[str, list[str]] = {
    "kube-bench": ["CM-6", "SI-7"],
    "cis-java":   ["CM-6", "SC-13"],
}


def parse_cis_text(
    raw_output: str,
    scanner: str,
    control_mapper: ControlMapper,
) -> list[Finding]:
    """Parse kube-bench / cis-java plain-text output into Findings.

    `scanner` must be the canonical name ("kube-bench" or "cis-java") —
    the caller (server/app.py) resolves aliases before calling here.
    """
    if scanner not in _SEVERITY_MAP:
        logger.warning("parse_cis_text: unknown scanner %r — no findings", scanner)
        return []

    fail_sev, warn_sev = _SEVERITY_MAP[scanner]
    fallback_controls = _CONTROL_FALLBACK[scanner]

    findings: list[Finding] = []
    summary_section = False

    for raw_line in raw_output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        # Skip summary blocks — they restate counts that the per-check
        # lines already encode and would otherwise produce phantom
        # findings if they happen to contain bracketed tokens.
        if line.startswith("==") or line.startswith("==="):
            summary_section = "summary" in line.lower()
            continue
        if summary_section:
            continue

        match = _LINE.match(line)
        if not match:
            continue

        status, rule_id, description = match.group(1), match.group(2), match.group(3)
        if status in ("PASS", "INFO"):
            continue

        severity = fail_sev if status == "FAIL" else warn_sev

        mapped = control_mapper.map_finding(scanner, rule_id, severity)
        control_ids = mapped or list(fallback_controls)

        findings.append(
            Finding(
                source=scanner,
                rule_id=rule_id,
                severity=severity,
                file="",     # CIS-style checks are config-level, not file-level
                line=0,
                message=f"[{status}] {rule_id} {description}".strip(),
                control_ids=control_ids,
                product="",
            )
        )

    logger.info(
        "parse_cis_text(%s): %d findings from %d lines",
        scanner, len(findings), len(raw_output.splitlines()),
    )
    return findings
