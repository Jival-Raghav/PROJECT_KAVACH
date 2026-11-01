.PHONY: check test lint run-backend run-frontend

check: lint test

lint:
	.\.venv\Scripts\ruff.exe check backend tests

test:
	.\.venv\Scripts\pytest.exe -v tests/

run-backend:
	.\.venv\Scripts\uvicorn.exe backend.main:app --host 0.0.0.0 --port 8000 --reload

run-frontend:
	cd frontend && npm.cmd run dev

# ── Kill chain (macOS / Linux) ──
.PHONY: killchain bench-killchain
killchain:
	cd backend && ../.venv/bin/python -m killchain.cli run

bench-killchain:
	cd backend && ../.venv/bin/python -m killchain.cli run --skip-ingest && ../.venv/bin/python -m killchain.cli bench
