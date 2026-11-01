"""Kavach API: firewall kill-chain analysis."""
from __future__ import annotations

import pathlib
import sys

# Allow both `uvicorn backend.main:app` from the repo root and `uvicorn main:app` from backend/.
_backend_dir = pathlib.Path(__file__).resolve().parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.incidents import router as incidents_router
from api.live import router as live_router

app = FastAPI(title="Kavach: Kill Chain & Attack Path Analysis")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(incidents_router)
app.include_router(live_router)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
