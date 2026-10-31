"""Kill chain & attack path API (FR-7): incidents, paths, reach, reports, rules, runs."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query

from config import get_settings
from killchain.models import Incident
from killchain.pathgraph import TimelineStep
from killchain.pipeline import load_meta, load_run, run_killchain
from killchain.reach import ReachResult
from killchain.report import render_report
from killchain.rules import load_rules

router = APIRouter(prefix="/api", tags=["Kill Chain"])

# run_id becomes a directory name and part of DuckDB file paths: allow-list it.
RunId = Annotated[str, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]

_SUMMARY_KEYS = ("incident_id", "title", "risk_score", "severity", "first_seen", "last_seen",
                 "tactics", "stages", "raw_alert_count", "detection_count", "entities")
_state: dict[str, Any] = {"status": "idle", "stage": None, "error": None}
_lock = threading.Lock()


def _run_dir(run_id: str) -> Path:
    return Path(get_settings().KILLCHAIN_DATA_DIR) / "runs" / run_id


def _incident(incident_id: int, run_id: str) -> dict:
    inc = load_run(_run_dir(run_id)).get(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return inc


@router.get("/incidents")
def list_incidents(run_id: RunId = "firex", limit: int = Query(100, ge=1, le=1000),
                   min_risk: float = 0.0) -> list[dict]:
    rows = [{k: inc.get(k) for k in _SUMMARY_KEYS} for inc in load_run(_run_dir(run_id)).values()
            if inc.get("risk_score", 0) >= min_risk]
    rows.sort(key=lambda r: (-r["risk_score"], r["first_seen"]))
    return rows[:limit]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, run_id: RunId = "firex") -> dict:
    return _incident(incident_id, run_id)


@router.get("/incidents/{incident_id}/path")
def get_incident_path(incident_id: int, run_id: RunId = "firex") -> dict:
    inc = _incident(incident_id, run_id)
    return {"incident_id": incident_id, "title": inc["title"], "timeline": inc["timeline"],
            "path": inc["path"]}


@router.get("/incidents/{incident_id}/next")
def get_incident_next(incident_id: int, run_id: RunId = "firex") -> dict:
    return _incident(incident_id, run_id)["reach"]


@router.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: int, run_id: RunId = "firex", llm: bool = False) -> dict:
    inc = _incident(incident_id, run_id)
    if not llm:
        return inc["report"]
    model = Incident.model_validate({k: v for k, v in inc.items() if k in Incident.model_fields})
    return render_report(model, [TimelineStep(**s) for s in inc["timeline"]],
                         ReachResult(**inc["reach"]), use_llm=True)


@router.get("/killchain/rules")
def get_rules() -> list[dict]:
    return [{"id": r.id, "title": r.title, "technique": r.technique, "kind": r.kind,
             "severity": r.severity, "where": r.where, "selection": r.selection}
            for r in load_rules(Path(get_settings().KILLCHAIN_RULES_DIR))]


@router.get("/killchain/status")
def get_status(run_id: RunId = "firex") -> dict:
    meta = load_meta(_run_dir(run_id))
    status = _state["status"]
    if status == "idle" and meta:
        status = "complete"
    return {**_state, "status": status, "run_meta": meta}


@router.post("/killchain/run")
def start_run(run_id: RunId = "firex", skip_ingest: bool = True) -> dict:
    with _lock:
        if _state["status"] == "running":
            raise HTTPException(status_code=409, detail="A kill-chain run is already in progress")
        _state.update(status="running", stage="starting", error=None)

    def work() -> None:
        cfg = get_settings()
        try:
            run_killchain(Path(cfg.KILLCHAIN_LOG_PATH), _run_dir(run_id),
                          Path(cfg.KILLCHAIN_RULES_DIR), skip_ingest=skip_ingest,
                          progress=lambda s: _state.update(stage=s))
            _state.update(status="complete", stage="done")
        except Exception as exc:  # surfaced to the UI through /killchain/status
            _state.update(status="error", error=str(exc))

    threading.Thread(target=work, daemon=True).start()
    return {"status": "started"}
