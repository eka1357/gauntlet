.PHONY: dev test lint demo install

install:
	pip install -e ".[dev]"

dev:
	@echo "Starting backend on :8000 and web on :3000..."
	start /b uvicorn backend.api:app --reload --port 8000
	cd web && npm run dev

test:
	python -m pytest tests/ -v

lint:
	python -m ruff check backend/ target/ jobs/ tests/ scripts/
	cd web && npx tsc --noEmit

demo:
	python -m backend.orchestrator --demo
