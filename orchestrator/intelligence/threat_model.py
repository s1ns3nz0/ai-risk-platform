"""Threat model data format and static generator.

Defines dataclasses for AI-driven threat modeling based on actual
application components (SBOM, manifest, enriched CVEs).
AI implementation is added later — this module defines format + static generator only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import yaml

from orchestrator.controls.models import Control
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.types import ProductManifest


@dataclass
class ThreatActor:
    """위협 행위자."""

    id: str  # TA-001
    name: str  # "External Attacker"
    motivation: str  # "Financial gain"
    capability: str  # "moderate" | "high" | "nation-state"
    attack_surface: list[str]  # ["internet-facing API", "supply chain"]


@dataclass
class ThreatScenario:
    """구체적인 위협 시나리오."""

    id: str  # TS-001
    title: str  # "JWT token forgery via weak signing"
    actor: str  # TA-001 reference
    attack_vector: str  # STRIDE category: S/T/R/I/D/E
    mitre_technique: str  # ATT&CK: T1190, T1078, etc.
    target_component: str  # "PyJWT 1.7.1 (CVE-2022-29217, EPSS: 0.234)"
    preconditions: list[str]
    attack_steps: list[str]
    impact: str
    likelihood: str  # "high" — based on EPSS + exposure
    severity: str  # "critical"
    affected_controls: list[str]  # ["PCI-DSS-3.5.1", "ASVS-V3.5.3"]
    mitigation: str


@dataclass
class ThreatModel:
    """애플리케이션 위협 모델 — AI가 실제 컴포넌트 기반으로 생성."""

    product: str
    generated_at: str
    mode: str  # "ai" | "static"

    # 입력 (AI에 제공되는 컨텍스트)
    components: list[str]  # SBOM에서 추출한 실제 컴포넌트 목록
    architecture: dict[str, object]  # product manifest (deployment, integrations)
    data_classification: list[str]
    known_vulnerabilities: list[str]  # enriched CVEs

    # 출력 (AI가 생성)
    threat_actors: list[ThreatActor]
    threat_scenarios: list[ThreatScenario]
    attack_surface_summary: str
    risk_summary: str

    # 컨트롤 매핑
    controls_required: list[str] = field(default_factory=list)
    controls_covered: list[str] = field(default_factory=list)
    controls_gap: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        """Serialize to YAML format for evidence output."""
        data = {
            "threat_model": {
                "product": self.product,
                "generated_at": self.generated_at,
                "mode": self.mode,
                "attack_surface": self.attack_surface_summary,
                "threat_actors": [
                    {
                        "id": a.id,
                        "name": a.name,
                        "motivation": a.motivation,
                        "capability": a.capability,
                        "attack_surface": a.attack_surface,
                    }
                    for a in self.threat_actors
                ],
                "threat_scenarios": [
                    {
                        "id": s.id,
                        "title": s.title,
                        "actor": s.actor,
                        "attack_vector": s.attack_vector,
                        "mitre_technique": s.mitre_technique,
                        "target_component": s.target_component,
                        "preconditions": s.preconditions,
                        "attack_steps": s.attack_steps,
                        "impact": s.impact,
                        "likelihood": s.likelihood,
                        "severity": s.severity,
                        "affected_controls": s.affected_controls,
                        "mitigation": s.mitigation,
                    }
                    for s in self.threat_scenarios
                ],
                "controls_gap": self.controls_gap,
                "risk_summary": self.risk_summary,
            }
        }
        return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)


# Package name substring → ATT&CK technique mapping
_PACKAGE_MITRE_MAP: list[tuple[list[str], str, str]] = [
    # (keywords, technique_id, stride_category)
    (["jwt", "jose", "authlib", "oauthlib"], "T1078", "Spoofing (STRIDE-S)"),
    (["cryptography", "pycryptodome", "pyopenssl"], "T1557", "Tampering (STRIDE-T)"),
    (["django", "flask", "fastapi", "starlette", "tornado"], "T1190", "Tampering (STRIDE-T)"),
    (["requests", "urllib3", "httpx", "aiohttp"], "T1071", "Information Disclosure (STRIDE-I)"),
    (["psycopg2", "sqlalchemy", "pymongo", "mysql"], "T1190", "Tampering (STRIDE-T)"),
    (["pickle", "pyyaml", "lxml", "xmltodict"], "T1059", "Elevation of Privilege (STRIDE-E)"),
]


class StaticThreatModelGenerator:
    """Static threat model — AI 없이 컴포넌트 기반으로 위협 시나리오 생성.

    SBOM 컴포넌트 + EPSS enriched CVEs + product manifest를 분석하여
    template 기반 위협 시나리오를 생성.
    """

    def generate(
        self,
        manifest: ProductManifest,
        sbom_components: list[str],
        enriched_vulns: list[EnrichedVulnerability],
        controls: list[Control],
    ) -> ThreatModel:
        """Static threat model 생성."""
        attack_surface = self._identify_attack_surface(manifest)
        scenarios = self._generate_scenarios_from_vulns(enriched_vulns)

        # Default threat actor for static mode
        actors = [
            ThreatActor(
                id="TA-001",
                name="External Attacker",
                motivation="Financial gain",
                capability="moderate",
                attack_surface=attack_surface,
            ),
        ]

        # Controls gap calculation
        controls_required = sorted(
            {cid for s in scenarios for cid in s.affected_controls}
        )
        controls_covered = sorted({c.id for c in controls})
        controls_gap = sorted(set(controls_required) - set(controls_covered))

        cve_ids = [v.cve_id for v in enriched_vulns]
        n_scenarios = len(scenarios)
        n_components = len(sbom_components)
        n_cves = len(cve_ids)

        risk_summary = (
            f"{manifest.name} has {n_scenarios} threat scenario(s) "
            f"based on {n_components} SBOM components and {n_cves} known CVE(s)."
        )

        attack_surface_summary = self._build_attack_surface_summary(
            manifest, attack_surface
        )

        return ThreatModel(
            product=manifest.name,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            mode="static",
            components=sbom_components,
            architecture=manifest.deployment,
            data_classification=manifest.data_classification,
            known_vulnerabilities=cve_ids,
            threat_actors=actors,
            threat_scenarios=scenarios,
            attack_surface_summary=attack_surface_summary,
            risk_summary=risk_summary,
            controls_required=controls_required,
            controls_covered=controls_covered,
            controls_gap=controls_gap,
        )

    def _identify_attack_surface(self, manifest: ProductManifest) -> list[str]:
        """Product manifest에서 공격 표면 식별."""
        surfaces: list[str] = []

        # External integrations → internet-facing
        external = [i for i in manifest.integrations if "external" in i.lower()]
        if external:
            surfaces.append("internet-facing API")
            for ext in external:
                surfaces.append(f"{ext} integration")

        # Data classification → data handling surface
        if "PCI" in manifest.data_classification:
            surfaces.append("PCI cardholder data handling")
        if "PII-financial" in manifest.data_classification:
            surfaces.append("financial PII handling")

        # Deployment → infrastructure surface
        deploy = manifest.deployment
        cloud = str(deploy.get("cloud", ""))
        region = str(deploy.get("region", ""))

        compute = deploy.get("compute", [])
        if isinstance(compute, list):
            for c in compute:
                if isinstance(c, dict):
                    surfaces.append(f"{cloud} {c.get('type', '?')} ({c.get('description', '')})")
        elif isinstance(compute, str):
            surfaces.append(f"{cloud} {compute} deployment ({region})")

        databases = deploy.get("databases", [])
        if isinstance(databases, list):
            for db in databases:
                if isinstance(db, dict):
                    surfaces.append(f"{db.get('type', '?')} database ({db.get('description', '')})")

        storage = deploy.get("storage", [])
        if isinstance(storage, list):
            for s in storage:
                if isinstance(s, dict):
                    surfaces.append(f"{s.get('type', '?')} storage ({s.get('description', '')})")

        networking = deploy.get("networking", [])
        if isinstance(networking, list):
            for n in networking:
                if isinstance(n, dict):
                    if "gateway" in str(n.get("type", "")).lower() or "alb" in str(n.get("type", "")).lower():
                        surfaces.append(f"{n.get('type', '?')} — internet-facing ({n.get('description', '')})")

        # Supply chain
        if manifest.integrations:
            surfaces.append("supply chain")

        return surfaces

    def _generate_scenarios_from_vulns(
        self, enriched_vulns: list[EnrichedVulnerability]
    ) -> list[ThreatScenario]:
        """Enriched CVEs에서 구체적 위협 시나리오 도출.

        Scenario generation criteria:
        - EPSS > 0.1: actively exploited → always generate
        - EPSS unavailable + CVSS high/critical: generate based on severity
        - EPSS <= 0.1 + CVSS medium/low: skip
        """
        scenarios: list[ThreatScenario] = []
        for i, vuln in enumerate(enriched_vulns):
            # Decide whether to generate a scenario
            if vuln.epss_score is not None and vuln.epss_score > 0.1:
                pass  # EPSS says actively exploited → generate
            elif vuln.epss_score is None and vuln.priority in ("critical", "high"):
                pass  # No EPSS data but CVSS is high/critical → generate
            else:
                continue  # Low risk → skip

            epss_label = f"EPSS: {vuln.epss_score}" if vuln.epss_score is not None else "EPSS: N/A"
            mitre, stride = self._map_to_mitre(vuln)
            target = (
                f"{vuln.package} {vuln.installed_version} "
                f"({vuln.cve_id}, {epss_label})"
            )

            scenarios.append(
                ThreatScenario(
                    id=f"TS-{i + 1:03d}",
                    title=f"Exploit {vuln.cve_id} in {vuln.package}",
                    actor="TA-001",
                    attack_vector=stride,
                    mitre_technique=mitre,
                    target_component=target,
                    preconditions=[
                        f"Application uses {vuln.package} {vuln.installed_version}",
                        f"Vulnerability {vuln.cve_id} is exploitable ({epss_label}, severity: {vuln.priority})",
                    ],
                    attack_steps=[
                        f"Identify {vuln.package} {vuln.installed_version} in target",
                        f"Exploit {vuln.cve_id}",
                        f"Achieve {vuln.severity} impact",
                    ],
                    impact=f"Exploitation of {vuln.cve_id} in {vuln.package} ({vuln.severity})",
                    likelihood="high" if (vuln.epss_score or 0) > 0.3 else "medium",
                    severity=vuln.severity,
                    affected_controls=vuln.control_ids,
                    mitigation=f"Upgrade {vuln.package} to {vuln.fixed_version}",
                )
            )

        return scenarios

    def _map_to_mitre(self, vuln: EnrichedVulnerability) -> tuple[str, str]:
        """CVE 타입 → MITRE ATT&CK technique 매핑.

        Package name is matched against category keywords via substring.
        Returns (technique_id, stride_category).
        """
        pkg_lower = vuln.package.lower()
        for keywords, technique, stride in _PACKAGE_MITRE_MAP:
            if any(kw in pkg_lower for kw in keywords):
                return technique, stride
        # Default
        return "T1190", "Tampering (STRIDE-T)"

    @staticmethod
    def _build_attack_surface_summary(
        manifest: ProductManifest, surfaces: list[str]
    ) -> str:
        parts = [f"{manifest.name}"]
        if "PCI" in manifest.data_classification:
            parts.append("PCI scope")
        parts.append(f"{len(surfaces)} attack surface(s)")
        if surfaces:
            parts.append("; ".join(surfaces))
        return " — ".join(parts)
