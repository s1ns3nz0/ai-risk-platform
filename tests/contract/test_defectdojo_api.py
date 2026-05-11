"""Contract tests for DefectDojo API — uses recorded fixtures, no real API calls."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


class TestProductResponseContract:
    def test_product_list_has_required_fields(self) -> None:
        raw = (FIXTURES / "defectdojo_product_response.json").read_text()
        data = json.loads(raw)

        assert "count" in data
        assert "results" in data
        assert isinstance(data["results"], list)
        assert len(data["results"]) >= 1

        product = data["results"][0]
        assert "id" in product
        assert isinstance(product["id"], int)
        assert "name" in product
        assert isinstance(product["name"], str)

    def test_product_response_pagination(self) -> None:
        raw = (FIXTURES / "defectdojo_product_response.json").read_text()
        data = json.loads(raw)

        assert "next" in data
        assert "previous" in data


class TestImportResponseContract:
    def test_import_response_has_required_fields(self) -> None:
        raw = (FIXTURES / "defectdojo_import_response.json").read_text()
        data = json.loads(raw)

        assert "scan_type" in data
        assert "test_id" in data
        assert isinstance(data["test_id"], int)
        assert "engagement_id" in data
        assert "product_id" in data
        assert "statistics" in data

    def test_import_statistics_structure(self) -> None:
        raw = (FIXTURES / "defectdojo_import_response.json").read_text()
        data = json.loads(raw)

        stats = data["statistics"]
        assert "created" in stats
        assert isinstance(stats["created"], int)
        assert "closed" in stats
        assert "reactivated" in stats
        assert "left_untouched" in stats
