"""Risk profile loader with JSON Schema validation."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml

from orchestrator.types import RiskProfile

_SCHEMA_PATH = Path(__file__).parent / "schemas" / "profile_schema.json"


def load_profile(path: str) -> RiskProfile:
    """Load and validate a risk-profile.yaml file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    with open(_SCHEMA_PATH) as f:
        schema = json.load(f)

    jsonschema.validate(data, schema)

    rp = data["risk_profile"]
    return RiskProfile(
        frameworks=rp["frameworks"],
        risk_appetite=rp["risk_appetite"],
        thresholds=rp["thresholds"],
        failure_policy=rp["failure_policy"],
    )
