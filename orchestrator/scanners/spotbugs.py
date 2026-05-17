"""SpotBugs XML parser.

SpotBugs emits XML by default. CI pipelines typically base64-encode it
before stuffing into a JSON envelope (since JSON can't carry raw XML
as a structured value). This parser accepts either form.

XML shape (excerpt):
  <BugCollection version='4.8.3' ...>
    <Project ...>...</Project>
    <BugInstance type='EI_EXPOSE_REP' priority='2' category='MALICIOUS_CODE'>
      <Class classname='com.x.Foo'><SourceLine .../></Class>
      <Method ...><SourceLine .../></Method>
      <SourceLine classname='com.x.Foo' start='42' end='42'
                  sourcefile='Foo.java' sourcepath='com/x/Foo.java' />
      <LongMessage>Foo.method() may expose internal rep ...</LongMessage>
    </BugInstance>
    ...
  </BugCollection>

priority: 1=High, 2=Medium, 3=Low (legacy "rank" is 1..20 with lower=worse;
we use priority since it's always populated).
"""

from __future__ import annotations

import base64
import binascii
import logging
from xml.etree import ElementTree as ET

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


_PRIORITY_TO_SEVERITY = {
    "1": "high",
    "2": "medium",
    "3": "low",
}


def _decode_payload(raw: str) -> str:
    """Accept either raw XML or base64-encoded XML and return raw XML.

    Detection: XML always starts with `<` after optional whitespace. Anything
    else is treated as base64.
    """
    stripped = raw.lstrip()
    if stripped.startswith("<"):
        return raw
    try:
        decoded = base64.b64decode(raw, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return raw  # let the XML parser fail naturally if it's neither


class SpotbugsScanner:
    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    def parse_output(self, raw_output: str) -> list[Finding]:
        xml_text = _decode_payload(raw_output)

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning("SpotBugs XML parse failed: %s", exc)
            return []

        if root.tag != "BugCollection":
            logger.warning("SpotBugs payload not a BugCollection (got %r)", root.tag)
            return []

        findings: list[Finding] = []
        for bug in root.findall("BugInstance"):
            rule_id = bug.get("type") or ""
            if not rule_id:
                continue
            priority = bug.get("priority", "")
            severity = _PRIORITY_TO_SEVERITY.get(priority, "info")
            category = bug.get("category", "")
            # SpotBugs nests source location under multiple SourceLine elements.
            # Prefer the BugInstance-level one (most specific); fall back to
            # the first nested SourceLine.
            sl = bug.find("SourceLine")
            if sl is None:
                sl = bug.find(".//SourceLine")
            file_path = sl.get("sourcepath") if sl is not None else ""
            line_str = sl.get("start") if sl is not None else "0"
            try:
                line = int(line_str or 0)
            except ValueError:
                line = 0

            long_msg = bug.findtext("LongMessage") or ""
            short_msg = bug.findtext("ShortMessage") or ""
            message = (long_msg or short_msg or rule_id).strip()

            control_ids = self._control_mapper.map_finding(
                "spotbugs", rule_id, severity=severity,
            )
            findings.append(
                Finding(
                    source="spotbugs",
                    rule_id=rule_id,
                    severity=severity,
                    file=file_path or "",
                    line=line,
                    message=message + (f" [{category}]" if category else ""),
                    control_ids=control_ids,
                    product="",
                )
            )
        return findings
