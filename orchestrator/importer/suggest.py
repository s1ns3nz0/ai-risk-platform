"""Scanner Suggestion Engine — keyword-based scanner mapping for imported controls.

이 모듈은 AI가 아닌 키워드 매칭 기반.
제안일 뿐이며, 인간이 반드시 검토해야 함.

매핑 전략:
1. 컨트롤 title/description에서 키워드 추출
2. 키워드 → scanner 카테고리 매핑
3. scanner 카테고리 → 구체적 rules/check_ids 제안
"""

from __future__ import annotations

from typing import Any

import yaml

from orchestrator.importer.oscal import ImportedControl


class ScannerSuggester:
    """컨트롤 키워드 기반으로 scanner mapping을 제안.

    이 모듈은 AI가 아닌 키워드 매칭 기반.
    제안일 뿐이며, 인간이 반드시 검토해야 함.

    매핑 전략:
    1. 컨트롤 title/description에서 키워드 추출
    2. 키워드 → scanner 카테고리 매핑
    3. scanner 카테고리 → 구체적 rules/check_ids 제안
    """

    KEYWORD_MAP: dict[str, list[dict[str, object]]] = {
        # Access Control keywords
        "access control": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_1", "CKV_AWS_40", "CKV_AWS_61"]},
        ],
        "authentication": [
            {"scanner": "semgrep", "rules": ["python.lang.security.audit.hardcoded-password.*"]},
            {"scanner": "gitleaks"},
        ],
        "password": [
            {"scanner": "semgrep", "rules": ["python.lang.security.audit.hardcoded-password.*"]},
            {"scanner": "gitleaks"},
        ],
        # Encryption keywords
        "encrypt": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_19", "CKV_AWS_145"]},
            {"scanner": "semgrep", "rules": ["python.cryptography.security.*"]},
        ],
        "cryptograph": [
            {"scanner": "semgrep", "rules": ["python.cryptography.security.*", "python.lang.security.audit.weak-hashing.*"]},
        ],
        # Network keywords
        "network": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_150"]},
        ],
        "firewall": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_24", "CKV_AWS_260"]},
        ],
        # Vulnerability management
        "vulnerability": [
            {"scanner": "grype", "severity_threshold": "high"},
            {"scanner": "sbom"},
        ],
        "patch": [
            {"scanner": "grype", "severity_threshold": "high"},
        ],
        "software component": [
            {"scanner": "sbom"},
            {"scanner": "grype", "severity_threshold": "medium"},
        ],
        # Logging / monitoring
        "audit": [
            {"scanner": "sigma"},
            {"scanner": "checkov", "check_ids": ["CKV_AWS_67", "CKV_AWS_18"]},
        ],
        "log": [
            {"scanner": "sigma"},
            {"scanner": "checkov", "check_ids": ["CKV_AWS_67", "CKV_AWS_35"]},
        ],
        "monitor": [
            {"scanner": "sigma"},
        ],
        "detect": [
            {"scanner": "sigma"},
        ],
        # Input validation
        "input validation": [
            {"scanner": "semgrep", "rules": ["python.lang.security.injection.*"]},
        ],
        "injection": [
            {"scanner": "semgrep", "rules": ["python.lang.security.injection.*", "python.lang.security.audit.formatted-sql-query.*"]},
        ],
        # Secrets
        "credential": [
            {"scanner": "gitleaks"},
            {"scanner": "semgrep", "rules": ["python.lang.security.audit.hardcoded-password.*"]},
        ],
        "secret": [
            {"scanner": "gitleaks"},
        ],
        "key management": [
            {"scanner": "gitleaks"},
            {"scanner": "checkov", "check_ids": ["CKV_AWS_33"]},
        ],
    }

    def suggest(self, control: ImportedControl) -> list[dict[str, object]]:
        """컨트롤의 title + description에서 키워드를 매칭하여 scanner 제안.

        Returns: 제안된 verification_methods 리스트.
        제안은 best-effort — 인간 검토 필요.
        """
        text = f"{control.title} {control.description}".lower()

        # Collect all matched entries
        matched: list[dict[str, object]] = []
        for keyword, entries in self.KEYWORD_MAP.items():
            if keyword in text:
                matched.extend(entries)

        # Merge by scanner: combine check_ids and rules, keep first severity_threshold
        merged: dict[str, dict[str, Any]] = {}
        for entry in matched:
            scanner = str(entry["scanner"])
            if scanner not in merged:
                merged[scanner] = {"scanner": scanner}

            existing = merged[scanner]

            if "check_ids" in entry:
                prev: list[Any] = list(existing.get("check_ids") or [])
                for cid in entry["check_ids"]:  # type: ignore[attr-defined]
                    if cid not in prev:
                        prev.append(cid)
                existing["check_ids"] = prev

            if "rules" in entry:
                prev_rules: list[Any] = list(existing.get("rules") or [])
                for rule in entry["rules"]:  # type: ignore[attr-defined]
                    if rule not in prev_rules:
                        prev_rules.append(rule)
                existing["rules"] = prev_rules

            if "severity_threshold" in entry and "severity_threshold" not in existing:
                existing["severity_threshold"] = entry["severity_threshold"]

        return list(merged.values())

    def apply_suggestions(
        self,
        controls: list[ImportedControl],
        output_path: str,
    ) -> tuple[int, int]:
        """컨트롤 리스트에 제안을 적용하여 YAML 생성.

        Returns: (제안된 컨트롤 수, 제안 없는 컨트롤 수)
        제안 없는 컨트롤은 verification_methods: [] 유지.
        """
        suggested_count = 0
        no_suggestion_count = 0

        entries = []
        for ctrl in controls:
            suggestions = self.suggest(ctrl)
            if suggestions:
                suggested_count += 1
                vms = []
                for s in suggestions:
                    vm: dict[str, object] = {
                        "scanner": s["scanner"],
                        "status": "suggested — review required",
                    }
                    if "check_ids" in s:
                        vm["check_ids"] = s["check_ids"]
                    if "rules" in s:
                        vm["rules"] = s["rules"]
                    if "severity_threshold" in s:
                        vm["severity_threshold"] = s["severity_threshold"]
                    vms.append(vm)
            else:
                no_suggestion_count += 1
                vms = []

            entry = {
                "control": {
                    "id": ctrl.id,
                    "title": ctrl.title,
                    "framework": ctrl.framework,
                    "description": ctrl.description,
                    "verification_methods": vms,
                }
            }
            entries.append(entry)

        doc = {"controls": entries}
        with open(output_path, "w") as f:
            yaml.dump(doc, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        return suggested_count, no_suggestion_count
