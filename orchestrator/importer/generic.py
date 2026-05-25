"""Non-OSCAL framework parsers (custom JSON)."""

from __future__ import annotations

import json
from typing import Any

from orchestrator.importer.oscal import ImportedControl


class GenericFrameworkParser:
    """비-OSCAL 소스 파싱. 커스텀 JSON 포맷 (id, title, description)."""

    def parse_generic_json(
        self,
        path: str,
        framework_id: str,
        id_field: str = "id",
        title_field: str = "title",
        description_field: str = "description",
    ) -> list[ImportedControl]:
        """커스텀 JSON 매핑."""
        with open(path) as f:
            data = json.load(f)

        items: list[dict[str, Any]]
        if isinstance(data, dict):
            items = data.get("controls") or data.get("items") or []
        else:
            items = data

        return [
            ImportedControl(
                id=item[id_field],
                title=item.get(title_field, ""),
                description=item.get(description_field, ""),
                framework=framework_id,
                properties={},
            )
            for item in items
        ]
