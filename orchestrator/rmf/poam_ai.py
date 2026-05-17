"""Bedrock POA&M enricher.

For each generated POA&M item, asks Claude to fill the human-readable
fields the static templates only stub: weakness description, business
impact, remediation plan/resources/vendor dependency, and a tighter
milestone breakdown.

Failure-tolerant by design — any per-item exception logs and falls back
to the static template that POAMGenerator already produced. Runs in
parallel via ThreadPoolExecutor to amortise Bedrock latency.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from orchestrator.rmf.poam import POAMItem

logger = logging.getLogger(__name__)


_PROMPT_TEMPLATE = """\
You are a security engineer drafting a single POA&M item for a CI/CD platform.

Vulnerability:
  finding_id:        {finding_id}
  scanner:           {scanner}
  scan_type:         {scan_type}
  severity:          {severity}
  cvss_score:        {cvss}
  epss_score:        {epss}
  package:           {package}
  installed_version: {installed}
  fixed_version:     {fixed}
  message:           {message}

Affected product:
  name:                {product}
  data_classification: {data_class}
  CIA impact_levels:   {cia}

SLA deadline (days from now): {sla_days}

Return a SINGLE JSON object (no prose, no markdown fences) with these keys:
  description:         1-2 sentence plain-English explanation of the weakness
  business_impact:     1-2 sentences on what this specifically means for {product}
  remediation_plan:    concrete steps to fix it (1-3 sentences)
  resources_required:  e.g. "1 engineer, 0.5 day"
  vendor_dependency:   short string, or "" if none
  milestones:          array of 3 objects, each {{"description": "...", "target_date": "+Xd"}},
                       where target_date is a relative offset like "+1d", "+15d", "+30d"

Strict rules:
- Output JSON only.
- Never include any field not listed above.
- Keep each text field under 400 characters.
"""


class BedrockPOAMEnricher:
    """Mutates POAMItem objects in-place with model-generated text.

    The infrastructure mirrors RiskAssessmentPipeline: per-item prompt,
    parallel execution capped by `max_workers`, static fallback on error.
    """

    def __init__(
        self,
        bedrock_client: Any,
        max_workers: int = 4,
        max_tokens: int = 1024,
    ) -> None:
        self._client = bedrock_client
        self._max_workers = max_workers
        self._max_tokens = max_tokens
        self._lock = threading.Lock()

    def enrich(self, items: list[POAMItem]) -> dict[str, int]:
        """Enrich every POA&M item in place. Returns {enriched, failed} counts."""
        if not items:
            return {"enriched": 0, "failed": 0}

        result = {"enriched": 0, "failed": 0}
        with ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="poam-ai") as pool:
            futures = {pool.submit(self._enrich_one, item): item for item in items}
            for fut in as_completed(futures):
                item = futures[fut]
                try:
                    fut.result()
                    with self._lock:
                        result["enriched"] += 1
                except Exception as exc:
                    logger.warning("POA&M enrichment failed for %s: %s", item.id, exc)
                    with self._lock:
                        result["failed"] += 1
        return result

    def _enrich_one(self, item: POAMItem) -> None:
        prompt = self._build_prompt(item)
        raw = self._client.invoke(prompt, max_tokens=self._max_tokens)
        data = _extract_json(raw)
        if not isinstance(data, dict):
            raise ValueError("model output was not a JSON object")
        _apply_to_item(item, data)

    @staticmethod
    def _build_prompt(item: POAMItem) -> str:
        w = item.weakness_detail
        s = item.source_detail
        i = item.impact
        return _PROMPT_TEMPLATE.format(
            finding_id=item.finding_id or w.cve_id or "?",
            scanner=s.scanner,
            scan_type=s.scan_type,
            severity=item.severity,
            cvss=w.cvss_score if w.cvss_score is not None else "?",
            epss=w.epss_score if w.epss_score is not None else "?",
            package=w.package or "?",
            installed=item.weakness_detail.package and getattr(item, "_installed", "?") or "?",
            fixed=item.weakness_detail.package and getattr(item, "_fixed", "?") or "?",
            message=(item.weakness or "")[:300].replace("\n", " "),
            product=i.affected_asset or "?",
            data_class=", ".join(i.data_classification) or "?",
            cia=", ".join(f"{k}={v}" for k, v in i.cia.items()) or "?",
            sla_days=item.lifecycle.sla_days,
        )


def _extract_json(raw: str) -> Any:
    """Models sometimes wrap JSON in ```json fences or chatty preamble.
    Pull the first top-level {…} balanced block out."""
    if not raw:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        body = fence.group(1)
    else:
        start = raw.find("{")
        if start == -1:
            return None
        body = raw[start:]
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        # Last-resort: try to slice at the matching brace.
        depth = 0
        for idx, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(body[: idx + 1])
                    except json.JSONDecodeError:
                        return None
        return None


def _apply_to_item(item: POAMItem, data: dict[str, Any]) -> None:
    """Merge model output into the structured fields. Silently ignores
    unknown keys and clamps text to a sane length."""
    def _s(key: str, limit: int = 400) -> str:
        v = data.get(key, "")
        return str(v)[:limit] if v else ""

    desc = _s("description")
    if desc:
        item.weakness_detail.description = desc

    bi = _s("business_impact")
    if bi:
        item.impact.business_impact = bi

    plan = _s("remediation_plan")
    if plan:
        item.remediation.plan = plan

    res = _s("resources_required", 200)
    if res:
        item.remediation.resources_required = res

    vd = _s("vendor_dependency", 200)
    # Empty string is a valid signal ("no vendor dependency") — only assign
    # when the key was explicitly present.
    if "vendor_dependency" in data:
        item.remediation.vendor_dependency = vd

    ms = data.get("milestones")
    if isinstance(ms, list) and ms:
        # Keep only objects with the right shape; replace template milestones.
        cleaned = [
            {
                "description": str(m.get("description", ""))[:200],
                "target_date": str(m.get("target_date", ""))[:30],
                "status": "open",
            }
            for m in ms if isinstance(m, dict)
        ]
        if cleaned:
            item.milestones = cleaned
