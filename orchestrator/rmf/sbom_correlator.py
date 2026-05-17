"""SBOM correlator — maps a Finding's package back to its CycloneDX
component so POA&M items can carry a stable `source_detail.sbom_ref`.

CycloneDX component shape (relevant fields):
  {
    "type": "library",
    "bom-ref": "pkg:maven/org.springframework/spring-core@6.1.6",
    "name": "spring-core",
    "version": "6.1.6",
    "purl": "pkg:maven/org.springframework/spring-core@6.1.6",
    "group": "org.springframework"
  }

Match precedence (most specific wins):
  1. exact PURL match (Trivy/Grype emit PURLs in some fields)
  2. group:name + version
  3. name + version
  4. name only (fallback — typically wrong, but better than nothing)

Reference format we emit: "bom.json#components/{bom-ref-or-purl-or-name@version}"
matching the CycloneDX 1.5 component-reference convention.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class SbomCorrelator:
    """Builds package@version → bom-ref index once, then answers per-finding."""

    def __init__(self, sbom: dict[str, Any] | None) -> None:
        self._by_purl: dict[str, str] = {}
        self._by_name_version: dict[tuple[str, str], str] = {}
        self._by_group_name_version: dict[tuple[str, str, str], str] = {}
        self._by_name: dict[str, str] = {}
        self._load(sbom)

    def _load(self, sbom: dict[str, Any] | None) -> None:
        if not isinstance(sbom, dict):
            return
        components = sbom.get("components", [])
        if not isinstance(components, list):
            return
        for comp in components:
            if not isinstance(comp, dict):
                continue
            ref = str(
                comp.get("bom-ref")
                or comp.get("purl")
                or self._fallback_ref(comp)
                or "",
            )
            if not ref:
                continue
            purl = str(comp.get("purl", ""))
            name = str(comp.get("name", ""))
            version = str(comp.get("version", ""))
            group = str(comp.get("group", ""))
            if purl:
                self._by_purl[purl] = ref
            if name and version:
                self._by_name_version.setdefault((name, version), ref)
                if group:
                    self._by_group_name_version.setdefault((group, name, version), ref)
            if name:
                self._by_name.setdefault(name, ref)

    @staticmethod
    def _fallback_ref(comp: dict[str, Any]) -> str:
        n, v = comp.get("name", ""), comp.get("version", "")
        return f"{n}@{v}" if n and v else ""

    def correlate(self, package: str, installed_version: str = "") -> str:
        """Return a `bom.json#...` reference, or "" when no match."""
        if not package:
            return ""

        # 1. PURL match (Trivy `PkgPath`/`PkgPURL` would come here if extracted).
        purl_ref = self._by_purl.get(package)
        if purl_ref:
            return self._format(purl_ref)

        # 2. group:name+version (handles Maven coordinates like
        #    "org.springframework:spring-core")
        if ":" in package and installed_version:
            group, _, name = package.partition(":")
            ref = self._by_group_name_version.get((group, name, installed_version))
            if ref:
                return self._format(ref)
            # also try name+version directly (in case SBOM lacks group)
            ref = self._by_name_version.get((name, installed_version))
            if ref:
                return self._format(ref)

        # 3. name+version
        if installed_version:
            ref = self._by_name_version.get((package, installed_version))
            if ref:
                return self._format(ref)

        # 4. name only (last resort)
        ref = self._by_name.get(package)
        if ref:
            return self._format(ref)

        # Some Maven coordinates: try just the artifact portion.
        if ":" in package:
            artifact = package.split(":")[-1]
            ref = self._by_name.get(artifact)
            if ref:
                return self._format(ref)

        return ""

    @staticmethod
    def _format(ref: str) -> str:
        return f"bom.json#components/{ref}"
