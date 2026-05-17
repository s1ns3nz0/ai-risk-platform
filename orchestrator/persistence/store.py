"""File-based assessment store.

Layout (one file per assessment):
  <root>/<product>/risk-assessments/<assessment_id>.json

Assessment ID is `RA-{date}-{hash}` where hash is a short uuid suffix. IDs are
stable across reads so the pipeline can link back to the original run.

This is intentionally a flat, file-based store — easy to inspect with
`kubectl exec` + `cat`, easy to back up, no schema migrations. For
multi-replica deployments mount the root as a shared PVC, or swap this
class for a Redis/Postgres backend (same public interface).
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AssessmentRecord:
    """Serialized assessment + its POA&M items, indexed by id."""

    id: str
    product: str
    created_at: str
    payload: dict[str, Any] = field(default_factory=dict)  # full AssessmentResult.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "product": self.product,
            "created_at": self.created_at,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssessmentRecord":
        return cls(
            id=data["id"],
            product=data["product"],
            created_at=data["created_at"],
            payload=data.get("payload", {}),
        )


class AssessmentStore:
    """Thread-safe file-based store for completed assessments.

    Concurrent writers across replicas writing to the same PVC works because
    each assessment has a unique id (uuid suffix); collisions are negligible.
    Per-file rewrites use an atomic temp-file + rename so a partial write
    can't corrupt the JSON.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._lock = threading.Lock()
        self._root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def new_id() -> str:
        return f"RA-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

    def _product_dir(self, product: str) -> Path:
        # Reuse the existing controls/products/{p}/risk-assessments/ convention
        # the CLI already writes to, so on-disk shapes stay consistent.
        d = self._root / product / "risk-assessments"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _path(self, product: str, assessment_id: str) -> Path:
        return self._product_dir(product) / f"{assessment_id}.json"

    # ---- save ----
    def save(self, record: AssessmentRecord) -> Path:
        path = self._path(record.product, record.id)
        tmp = path.with_suffix(".json.tmp")
        with self._lock:
            tmp.write_text(json.dumps(record.to_dict(), indent=2, default=str))
            tmp.replace(path)
        logger.info("assessment saved: product=%s id=%s path=%s", record.product, record.id, path)
        return path

    # ---- read ----
    def get(self, product: str, assessment_id: str) -> AssessmentRecord | None:
        path = self._path(product, assessment_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("failed to read %s: %s", path, exc)
            return None
        return AssessmentRecord.from_dict(data)

    def list_for_product(self, product: str) -> list[dict[str, Any]]:
        """Lightweight listing — returns id + created_at only, no payload.
        Sorted newest-first."""
        d = self._product_dir(product)
        records: list[dict[str, Any]] = []
        for path in d.glob("RA-*.json"):
            try:
                data = json.loads(path.read_text())
                records.append({
                    "id": data["id"],
                    "product": data["product"],
                    "created_at": data["created_at"],
                })
            except (json.JSONDecodeError, KeyError, OSError):
                continue
        records.sort(key=lambda r: r["created_at"], reverse=True)
        return records

    # ---- POA&M item updates ----
    def update_poam_section(
        self,
        product: str,
        assessment_id: str,
        poam_id: str,
        section: str,
        values: dict[str, Any],
    ) -> AssessmentRecord | None:
        """Merge `values` into the named section (`ticket`, `delay`,
        `risk_acceptance`, `verification`) of the POA&M item.

        Returns the updated record, or None if no such assessment/poam exists.
        """
        allowed = {"ticket", "delay", "risk_acceptance", "verification"}
        if section not in allowed:
            raise ValueError(f"section must be one of {sorted(allowed)}")

        with self._lock:
            record = self.get(product, assessment_id)
            if record is None:
                return None
            items = record.payload.get("poam", {}).get("items", [])
            target = next((it for it in items if it.get("id") == poam_id), None)
            if target is None:
                return None
            target.setdefault(section, {}).update(values)
            # Auto-stamp verification timestamp when caller omitted it (or
            # sent the empty default).
            if section == "verification" and not target[section].get("verified_at"):
                target[section]["verified_at"] = datetime.now(timezone.utc).isoformat()
            # Atomic write back.
            path = self._path(product, assessment_id)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(record.to_dict(), indent=2, default=str))
            tmp.replace(path)
            return record
