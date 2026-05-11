"""Baseline YAML generator from ImportedControl list."""

from __future__ import annotations

import yaml

from orchestrator.importer.oscal import ImportedControl

_DEFAULT_TIERS = ["high", "critical"]


class BaselineGenerator:
    """ImportedControl 리스트 → baseline YAML 파일.

    출력 형식은 기존 baselines/*.yaml과 동일.
    verification_methods는 비어있음 — 인간이 매핑해야 함.
    """

    def generate(
        self,
        controls: list[ImportedControl],
        output_path: str,
        applicable_tiers: list[str] | None = None,
    ) -> str:
        """YAML 파일 생성. verification_methods: [] (빈 상태).

        Returns: 생성된 파일 경로.
        """
        tiers = applicable_tiers or _DEFAULT_TIERS

        entries = []
        for ctrl in controls:
            entry = {
                "control": {
                    "id": ctrl.id,
                    "title": ctrl.title,
                    "framework": ctrl.framework,
                    "description": ctrl.description,
                    "verification_methods": [],
                    "applicable_tiers": tiers,
                }
            }
            entries.append(entry)

        doc = {"controls": entries}

        with open(output_path, "w") as f:
            yaml.dump(doc, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        return output_path
