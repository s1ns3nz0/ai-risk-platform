"""Tests for docker-compose.yml structure and configuration."""

from pathlib import Path

import yaml

COMPOSE_PATH = Path(__file__).parent.parent.parent / "docker-compose.yml"

REQUIRED_SERVICES = {
    "uwsgi",
    "defectdojo-nginx",
    "defectdojo-celery-beat",
    "defectdojo-celery-worker",
    "defectdojo-postgres",
    "defectdojo-redis",
}


def test_compose_file_valid_yaml() -> None:
    """docker-compose.yml must be valid YAML."""
    content = COMPOSE_PATH.read_text()
    data = yaml.safe_load(content)
    assert isinstance(data, dict)


def test_compose_has_required_services() -> None:
    """All 6 DefectDojo services must be defined."""
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    services = set(data.get("services", {}).keys())
    assert REQUIRED_SERVICES.issubset(services), (
        f"Missing services: {REQUIRED_SERVICES - services}"
    )


def test_postgres_has_persistent_volume() -> None:
    """Postgres service must use a named volume for data persistence."""
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    postgres = data["services"]["defectdojo-postgres"]
    volumes = postgres.get("volumes", [])
    # At least one volume mapping should reference the named volume
    volume_strings = [v if isinstance(v, str) else v.get("source", "") for v in volumes]
    assert any("defectdojo-postgres-data" in v for v in volume_strings), (
        "Postgres must have a persistent named volume"
    )
    # Named volume must be declared at top level
    top_volumes = data.get("volumes", {})
    assert "defectdojo-postgres-data" in top_volumes


def test_defectdojo_images_have_platform() -> None:
    """DefectDojo images must specify platform: linux/amd64 for ARM compatibility."""
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    dd_services = [
        name for name, svc in data["services"].items()
        if "defectdojo" in svc.get("image", "") or name == "uwsgi"
    ]
    for name in dd_services:
        svc = data["services"][name]
        assert svc.get("platform") == "linux/amd64", (
            f"Service {name} missing platform: linux/amd64 (required for Apple Silicon)"
        )


def test_ports_bind_to_localhost() -> None:
    """Exposed ports must bind to 127.0.0.1, never 0.0.0.0."""
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    for name, svc in data["services"].items():
        for port in svc.get("ports", []):
            port_str = str(port)
            assert "0.0.0.0" not in port_str, (
                f"Service {name} binds to 0.0.0.0 — use 127.0.0.1"
            )
            # If port is exposed, it should explicitly bind to 127.0.0.1
            if ":" in port_str:
                assert port_str.startswith("127.0.0.1:"), (
                    f"Service {name} port {port_str} must bind to 127.0.0.1"
                )
