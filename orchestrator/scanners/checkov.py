"""Checkov scanner wrapper — IaC policy gate."""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 300  # 5 minutes

# Checkov community edition does not emit severity for most checks.
# This map assigns severity based on Bridgecrew/Prisma Cloud severity data.
# Checks not in this map default to "medium".
_CHECKOV_SEVERITY: dict[str, str] = {
    # Critical — direct data exposure or full access
    "CKV_AWS_41": "critical",   # IAM policy with full admin privileges
    "CKV_AWS_40": "critical",   # IAM policy allows * on *
    "CKV_AWS_61": "critical",   # IAM policy with escalation permissions
    "CKV_AWS_63": "critical",   # S3 bucket policy grants public access
    "CKV_AWS_20": "critical",   # S3 bucket is publicly accessible
    "CKV_AWS_57": "critical",   # S3 bucket has public ACL
    # High — significant security weaknesses
    "CKV_AWS_24": "high",       # Security group allows ingress 0.0.0.0/0 to port 22
    "CKV_AWS_25": "high",       # Security group allows ingress 0.0.0.0/0 to port 3389
    "CKV_AWS_23": "high",       # Security group allows ingress 0.0.0.0/0
    "CKV_AWS_19": "high",       # S3 bucket without server-side encryption
    "CKV_AWS_18": "high",       # S3 bucket without access logging
    "CKV_AWS_21": "high",       # S3 bucket without versioning
    "CKV_AWS_145": "high",      # RDS instance not encrypted
    "CKV_AWS_16": "high",       # RDS instance not encrypted
    "CKV_AWS_17": "high",       # RDS instance logging disabled
    "CKV_AWS_1": "high",        # IAM policy overly permissive
    "CKV_AWS_2": "high",        # ALB not using HTTPS
    "CKV_AWS_3": "high",        # EBS volume not encrypted
    "CKV_AWS_8": "high",        # Launch config is not public
    "CKV_AWS_46": "high",       # EC2 instance uses IMDSv1
    "CKV_AWS_79": "high",       # Instance metadata service v1 enabled
    "CKV_AWS_88": "high",       # EC2 instance is publicly accessible
    "CKV_AWS_260": "high",      # Security group allows unrestricted ingress
    "CKV_AWS_53": "high",       # S3 Block Public Access not configured
    "CKV_AWS_54": "high",       # S3 Block Public Policy not set
    "CKV_AWS_55": "high",       # S3 Block Public ACLs not set
    "CKV_AWS_56": "high",       # S3 RestrictPublicBuckets not set
    # Medium — best practice violations
    "CKV_AWS_26": "medium",     # SNS topic not encrypted
    "CKV_AWS_27": "medium",     # SQS queue not encrypted
    "CKV_AWS_28": "medium",     # DynamoDB table not encrypted
    "CKV_AWS_33": "medium",     # KMS key rotation disabled
    "CKV_AWS_35": "medium",     # CloudTrail log not encrypted
    "CKV_AWS_36": "medium",     # CloudTrail log file validation disabled
    "CKV_AWS_37": "medium",     # ELB access logs disabled
    "CKV_AWS_7": "medium",      # ECR image tag immutability
    "CKV_AWS_130": "medium",    # VPC subnet assigns public IP
    "CKV_AWS_68": "medium",     # WAF web ACL not associated with resource
    # Secrets (from Checkov secrets scanner)
    "CKV_SECRET_1": "critical", # Hardcoded secret detected
    "CKV_SECRET_2": "critical",
    "CKV_SECRET_3": "critical",
    "CKV_SECRET_4": "critical",
    "CKV_SECRET_5": "critical",
    "CKV_SECRET_6": "critical",
    "CKV_SECRET_7": "critical",
    "CKV_SECRET_8": "critical",
    "CKV_SECRET_9": "critical",
    "CKV_SECRET_10": "critical",
    "CKV_SECRET_11": "critical",
    "CKV_SECRET_12": "critical",
    "CKV_SECRET_13": "critical",
    "CKV_SECRET_14": "critical",
}


class CheckovScanner:
    """Checkov IaC scanner wrapper."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "checkov"

    def scan(self, target_path: str) -> list[Finding]:
        """Run checkov CLI and parse output."""
        result = subprocess.run(
            ["checkov", "-d", target_path, "--output", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if not result.stdout.strip():
            logger.warning("Checkov produced no output. stderr: %s", result.stderr[:500])
            return []
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse Checkov JSON output into Finding objects.

        Checkov outputs either:
        - A single dict: {"results": {"failed_checks": [...]}} (single framework)
        - A list of dicts: [{"results": ...}, {"results": ...}] (multiple frameworks)
        """
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("Checkov output is not valid JSON")
            return []

        # Normalize to list of result blocks
        if isinstance(data, dict):
            result_blocks = [data]
        elif isinstance(data, list):
            result_blocks = [item for item in data if isinstance(item, dict)]
        else:
            logger.warning("Unexpected Checkov output format: %s", type(data))
            return []

        findings: list[Finding] = []
        for block in result_blocks:
            results = block.get("results", {})
            if not isinstance(results, dict):
                continue

            failed_checks = results.get("failed_checks", [])
            if not isinstance(failed_checks, list):
                continue

            for check in failed_checks:
                if not isinstance(check, dict):
                    continue

                check_id = str(check.get("check_id", ""))
                if not check_id:
                    continue

                severity_raw = check.get("severity")
                if severity_raw:
                    severity = str(severity_raw).lower()
                else:
                    # Community edition lacks severity — use curated map
                    severity = _CHECKOV_SEVERITY.get(check_id, "medium")

                line_range = check.get("file_line_range", [0])
                line = int(line_range[0]) if isinstance(line_range, list) and line_range else 0

                control_ids = self._control_mapper.map_finding("checkov", check_id)

                findings.append(
                    Finding(
                        source="checkov",
                        rule_id=check_id,
                        severity=severity,
                        file=str(check.get("file_path", "")),
                        line=line,
                        message=str(check.get("check_name", "")),
                        control_ids=control_ids,
                        product="",
                    )
                )

        return findings
