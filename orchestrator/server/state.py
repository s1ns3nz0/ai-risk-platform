"""Server-wide state — loaded once at boot, reusable across requests.

The CLI re-loads controls baselines + product config on every invocation.
The server holds them in memory so each request only pays for the
assessment itself.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orchestrator.assessor.interface import RiskAssessor
from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.config.manifest import load_manifest
from orchestrator.config.profile import load_profile
from orchestrator.controls.repository import ControlsRepository
from orchestrator.types import ProductManifest, RiskProfile

logger = logging.getLogger(__name__)


@dataclass
class ProductConfig:
    name: str
    manifest: ProductManifest
    profile: RiskProfile
    product_dir: Path


@dataclass
class SharedClients:
    """Long-lived clients reused across requests.

    Built once at boot so the per-request hot path doesn't re-open
    boto3 sessions or HTTP connection pools.
    """

    assessor: RiskAssessor
    pipeline: Any  # RiskAssessmentPipeline | StaticRiskAssessmentPipeline
    epss_client: Any | None
    mode: str  # "bedrock" or "static"


class ServerState:
    """Holds the controls repository, product cache, shared clients, and scan-root allowlist."""

    def __init__(
        self,
        controls_dir: Path,
        tier_mappings_path: Path,
        products_dir: Path,
        rego_dir: Path,
        scan_roots: list[Path] | None = None,
    ) -> None:
        self._controls_dir = controls_dir
        self._tier_mappings_path = tier_mappings_path
        self._products_dir = products_dir
        self.rego_dir = rego_dir
        self.scan_roots = [r.resolve() for r in (scan_roots or [])]

        self._lock = threading.RLock()
        self._repo: ControlsRepository | None = None
        self._products: dict[str, ProductConfig] = {}
        self._clients: SharedClients | None = None

    # --- lifecycle ---

    def load(self) -> None:
        """Load (or re-load) controls, products, and shared clients."""
        with self._lock:
            repo = ControlsRepository(
                baselines_dir=str(self._controls_dir),
                tier_mappings_path=str(self._tier_mappings_path),
            )
            repo.load_all()
            self._repo = repo

            self._products = {}
            if self._products_dir.is_dir():
                for entry in self._products_dir.iterdir():
                    if not entry.is_dir():
                        continue
                    manifest_path = entry / "product-manifest.yaml"
                    profile_path = entry / "risk-profile.yaml"
                    if not manifest_path.exists() or not profile_path.exists():
                        continue
                    self._products[entry.name] = ProductConfig(
                        name=entry.name,
                        manifest=load_manifest(str(manifest_path)),
                        profile=load_profile(str(profile_path)),
                        product_dir=entry,
                    )

            self._clients = self._build_clients()

    def reload(self) -> dict[str, int]:
        """Re-read controls + products from disk. Returns counts."""
        self.load()
        return {
            "products": len(self._products),
            "controls_baselines": _count_baselines(self._controls_dir),
        }

    # --- accessors ---

    @property
    def controls_repo(self) -> ControlsRepository:
        with self._lock:
            if self._repo is None:
                raise RuntimeError("ServerState.load() must be called before use")
            return self._repo

    @property
    def clients(self) -> SharedClients:
        with self._lock:
            if self._clients is None:
                raise RuntimeError("ServerState.load() must be called before use")
            return self._clients

    def list_products(self) -> list[str]:
        with self._lock:
            return sorted(self._products.keys())

    def get_product(self, name: str) -> ProductConfig:
        with self._lock:
            if name not in self._products:
                raise KeyError(name)
            return self._products[name]

    def path_within_scan_roots(self, candidate: Path) -> bool:
        """True if `candidate` resolves under one of the configured scan roots.

        If scan_roots is empty, scan-mode is disabled — return False.
        """
        if not self.scan_roots:
            return False
        try:
            real = candidate.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            return False
        return any(_is_relative_to(real, root) for root in self.scan_roots)

    # --- internal ---

    def _build_clients(self) -> SharedClients:
        model_id = os.environ.get("BEDROCK_MODEL_ID")
        region = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")

        assessor: RiskAssessor = StaticRiskAssessor()
        pipeline: Any
        mode = "static"

        if model_id:
            try:
                from orchestrator.assessor.bedrock import BedrockRiskAssessor
                from orchestrator.assessor.bedrock_client import BedrockClient
                from orchestrator.rmf.pipeline import RiskAssessmentPipeline

                client = BedrockClient(model_id=model_id, region=region)
                assessor = BedrockRiskAssessor(client=client)
                pipeline = RiskAssessmentPipeline(bedrock_client=client)
                mode = "bedrock"
            except Exception as exc:
                logger.warning("Bedrock init failed, falling back to static: %s", exc)

        if mode == "static":
            from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline
            pipeline = StaticRiskAssessmentPipeline()

        epss_client: Any | None = None
        try:
            from orchestrator.intelligence.epss import EpssClient
            epss_client = EpssClient()
        except Exception as exc:
            logger.warning("EPSS client unavailable: %s", exc)

        return SharedClients(
            assessor=assessor, pipeline=pipeline, epss_client=epss_client, mode=mode,
        )


def _count_baselines(controls_dir: Path) -> int:
    if not controls_dir.is_dir():
        return 0
    return sum(1 for _ in controls_dir.glob("*.yaml"))


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
