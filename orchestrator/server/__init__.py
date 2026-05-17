"""HTTP API server mode — exposes assessment pipeline as REST endpoints.

Optional dependencies (install with `pip install -e .[server]`):
  - fastapi
  - uvicorn

Boot:
  python -m orchestrator serve --host 0.0.0.0 --port 8000
"""
