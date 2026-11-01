"""Live mode API: start/stop a streaming job, poll its status and change feed, list runs."""
from __future__ import annotations

import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from config import get_settings
from killchain.changes import read_changes
from killchain.live import LiveJob, is_zip, owner_alive, read_state
from killchain.pipeline import load_meta

router = APIRouter(prefix="/api", tags=["Live"])

RunId = Annotated[str, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]

# Live jobs of this process, keyed by run_id. Other processes (`cli live`) are recognised
# by the owner_pid / heartbeat_at they write into live_state.json.
_jobs: dict[str, LiveJob] = {}
_jobs_lock = threading.Lock()


class StartBody(BaseModel):
    path: str = Field(max_length=4096)
    run_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    schema_path: str | None = Field(default=None, max_length=4096)  # default: chosen automatically


def _runs_dir() -> Path:
    return Path(get_settings().KILLCHAIN_DATA_DIR) / "runs"


def _run_dir(run_id: str) -> Path:
    return _runs_dir() / run_id


def _alive(run_id: str) -> bool:
    job = _jobs.get(run_id)
    return job is not None and job.is_alive()


def _status(run_id: str, state: dict) -> str | None:
    """The file's status, or "interrupted" when nothing alive is processing the run."""
    status = state.get("status")
    if status != "processing":
        return status
    with _jobs_lock:
        if _alive(run_id):
            return status
    return status if owner_alive(state) else "interrupted"


@router.post("/live/start")
def start_live(body: StartBody) -> dict:
    run_id = body.run_id or datetime.now(UTC).strftime("live-%Y%m%d-%H%M%S")
    if run_id == "firex":
        raise HTTPException(400, "The firex run cannot be used for live mode")
    path = Path(body.path).expanduser()
    if not path.is_file():
        raise HTTPException(400, f"File not found: {body.path}")
    if not os.access(path, os.R_OK):
        raise HTTPException(400, f"File is not readable: {body.path}")
    if is_zip(path):
        raise HTTPException(400, f"Zip archives are not supported: {body.path}")
    schema = Path(body.schema_path).expanduser() if body.schema_path else None
    if schema is not None and not schema.is_file():
        raise HTTPException(400, f"Schema not found: {body.schema_path}")
    run_dir = _run_dir(run_id)
    if (run_dir / "run_meta.json").exists() and not (run_dir / "live_state.json").exists():
        raise HTTPException(400, f"Run {run_id} is a batch run and cannot be used for live mode")
    with _jobs_lock:
        if any(j.is_alive() for j in _jobs.values()):
            raise HTTPException(409, "A live job is already running")
        state = read_state(run_dir)
        if state is not None and state.get("status") == "complete":
            raise HTTPException(409, f"Run {run_id} is already complete")
        if state is not None and owner_alive(state):
            raise HTTPException(409, f"Run {run_id} is being processed by another process")
        s = get_settings()
        try:
            job = LiveJob(run_dir, path, Path(s.KILLCHAIN_RULES_DIR),
                          assets_path=Path(s.KILLCHAIN_ASSETS_PATH), schema_path=schema)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        _jobs[run_id] = job
        job.start()
    return {"run_id": run_id, "status": "processing"}


@router.get("/live/status")
def live_status(run_id: RunId) -> dict:
    state = read_state(_run_dir(run_id))
    if state is None:
        raise HTTPException(404, f"No live run {run_id}")
    return {**state, "status": _status(run_id, state)}


@router.get("/live/changes")
def live_changes(run_id: RunId, since_generation: int = Query(0, ge=0)) -> list[dict]:
    return read_changes(_run_dir(run_id), since_generation)


@router.post("/live/stop")
def stop_live(run_id: RunId) -> dict:
    with _jobs_lock:
        job = _jobs.get(run_id)
        if job is None or not job.is_alive():
            raise HTTPException(404, f"No live job running for {run_id}")
        job.stop()
    return {"status": "stopping"}


@router.get("/runs")
def list_runs() -> list[dict]:
    root = _runs_dir()
    if not root.is_dir():
        return []
    rows = []
    for d in root.iterdir():
        if not d.is_dir():
            continue
        live_f, meta_f = d / "live_state.json", d / "run_meta.json"
        if live_f.exists():
            state = read_state(d) or {}
            kind, f = "live", live_f
            status, path = _status(d.name, state), state.get("path")
        elif meta_f.exists():
            kind, f, status = "batch", meta_f, "complete"
            path = load_meta(d).get("log_path")
        else:
            continue
        mtime = f.stat().st_mtime
        rows.append((mtime, {"run_id": d.name, "kind": kind, "status": status,
                             "updated_at": datetime.fromtimestamp(mtime, UTC).isoformat(),
                             "path": path}))
    rows.sort(key=lambda r: -r[0])
    return [r[1] for r in rows]
