.PHONY: setup test test-contract lint demo demo-full docker-up docker-down docker-reset demo-docker

setup:
	pip install -e ".[dev]"

test:
	pytest tests/unit/ -v

test-contract:
	pytest tests/contract/ -v

lint:
	ruff check . && mypy orchestrator/

demo:
	@python -m orchestrator demo tests/fixtures/sample-app --product payment-api

demo-full:
	@BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6-20250514-v1:0 python -m orchestrator demo tests/fixtures/sample-app --product payment-api

docker-up:
	docker compose up -d
	@echo "DefectDojo starting at http://127.0.0.1:8080 (admin/admin)"
	@echo "First run takes ~5 minutes for initialization."

docker-down:
	docker compose down

docker-reset:
	docker compose down -v
	@echo "All data deleted."

demo-docker: docker-up
	@echo "Waiting for DefectDojo to be ready..."
	@sleep 30
	python -m orchestrator demo tests/fixtures/sample-app --product payment-api
