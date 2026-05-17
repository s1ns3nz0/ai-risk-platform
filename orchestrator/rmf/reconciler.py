"""Cross-run POA&M reconciliation.

Compares a freshly-saved assessment against the most recent prior
assessment for the same product. For every POA&M item in the prior run
whose fingerprint no longer appears in the new run, stamp
`lifecycle.closed_at` on the prior record. The new run is the source of
truth for what's still open.

Items already marked closed (`closed_at != null`) or formally accepted
(`risk_acceptance.accepted_by`) are skipped — once closed, stay closed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def reconcile_against_previous(store: Any, product: str, current_id: str) -> dict[str, int]:
    """Diff `current_id` against the most recent earlier assessment.

    Returns {`closed`: int, `still_open`: int, `previous_id`: str|""}.
    """
    summaries = store.list_for_product(product)
    # Drop the current one + anything created later (defensive against clock skew).
    prior_ids = [s["id"] for s in summaries if s["id"] != current_id]
    if not prior_ids:
        return {"closed": 0, "still_open": 0, "previous_id": ""}

    # list_for_product returns newest-first, so the first prior id is the
    # most recent earlier assessment.
    prior_id = prior_ids[0]
    current = store.get(product, current_id)
    previous = store.get(product, prior_id)
    if current is None or previous is None:
        return {"closed": 0, "still_open": 0, "previous_id": prior_id}

    current_fps = {
        item.get("fingerprint")
        for item in current.payload.get("poam", {}).get("items", [])
        if item.get("fingerprint")
    }

    closed = 0
    still_open = 0
    now = datetime.now(timezone.utc).isoformat()
    mutated = False

    for item in previous.payload.get("poam", {}).get("items", []):
        fp = item.get("fingerprint")
        if not fp:
            continue
        lifecycle = item.setdefault("lifecycle", {})
        if lifecycle.get("closed_at"):
            continue  # already closed
        if item.get("risk_acceptance", {}).get("accepted_by"):
            continue  # AO accepted; don't auto-close
        if fp in current_fps:
            still_open += 1
            continue
        lifecycle["closed_at"] = now
        closed += 1
        mutated = True

    if mutated:
        # Rewrite the previous record atomically via the store's save path.
        store.save(previous)
        logger.info(
            "reconciled product=%s prior=%s closed=%d still_open=%d",
            product, prior_id, closed, still_open,
        )

    return {"closed": closed, "still_open": still_open, "previous_id": prior_id}
