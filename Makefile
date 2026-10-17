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
