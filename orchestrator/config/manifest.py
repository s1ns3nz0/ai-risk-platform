"""Product manifest loader with JSON Schema validation."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml

from orchestrator.types import ProductManifest

_SCHEMA_PATH = Path(__file__).parent / "schemas" / "manifest_schema.json"


def load_manifest(path: str) -> ProductManifest:
    """Load and validate a product-manifest.yaml file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    with open(_SCHEMA_PATH) as f:
        schema = json.load(f)

    jsonschema.validate(data, schema)

    product = data["product"]
    impact_levels = product.get("impact_levels", {
        "confidentiality": "moderate",
        "integrity": "moderate",
        "availability": "moderate",
    })
    return ProductManifest(
        name=product["name"],
        description=product["description"],
        data_classification=product["data_classification"],
        jurisdiction=product["jurisdiction"],
        deployment=product.get("deployment", {}),
        integrations=product.get("integrations", []),
        mission=product.get("mission", {}),
        impact_levels=impact_levels,
    )
