#!/usr/bin/env bash
# Kavach — one-command setup & launch (macOS / Linux).
# Usage: ./run.sh            # setup (first time) + start backend and frontend
#        ./run.sh --test     # setup, then run the test suite and exit
set -euo pipefail
cd "$(dirname "$0")"

# ── Pick a Python 3.10+ ───────────────────────────────────────────────────────
PY=""
for c in python3.12 python3.11 python3.13 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3,10))'; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || { echo "ERROR: Python 3.10+ is required."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "ERROR: Node.js 18+ (npm) is required."; exit 1; }

# ── Python venv + deps (reinstalls only if requirements change) ───────────────
[ -d .venv ] || { echo "==> Creating virtualenv with $PY"; "$PY" -m venv .venv; }
# shellcheck disable=SC1091
source .venv/bin/activate
STAMP=.venv/.deps-stamp
if [ ! -f "$STAMP" ] || [ backend/requirements.txt -nt "$STAMP" ] || [ requirements.txt -nt "$STAMP" ]; then
  echo "==> Installing Python dependencies"
  pip install -q --upgrade pip
  pip install -q -r backend/requirements.txt -r requirements.txt
  touch "$STAMP"
fi

# ── .env (defaults to offline replay mode: no API key needed) ─────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  sed -i.bak 's/^LLM_REPLAY_ONLY=.*/LLM_REPLAY_ONLY=true/' .env && rm -f .env.bak
  echo "==> Created .env with LLM_REPLAY_ONLY=true (add GROQ_API_KEY and set it to 0 for live LLM calls)"
fi

if [ "${1:-}" = "--test" ]; then
  pytest tests/ -v
  exit 0
fi

# ── Frontend deps ─────────────────────────────────────────────────────────────
if [ ! -d frontend/node_modules ]; then
  echo "==> Installing frontend dependencies"
  (cd frontend && npm install)
fi

# ── Launch ────────────────────────────────────────────────────────────────────
cleanup() { echo; echo "Shutting down..."; kill 0 2>/dev/null || true; }
trap cleanup INT TERM EXIT

echo "==> Backend  : http://localhost:8000  (API docs: http://localhost:8000/docs)"
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir backend &

echo "==> Frontend : http://localhost:5173"
(cd frontend && npm run dev) &

wait
