"""Kill chain & attack path API (FR-7): incidents, paths, reach, reports, rules, runs."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from config import get_settings
from killchain import response
from killchain.compliance import evaluate_controls, load_controls
from killchain.models import Incident
from killchain.pathgraph import TimelineStep
from killchain.pipeline import load_accounts, load_actors, load_anomalies, load_meta, load_run, run_killchain
from killchain.reach import ReachResult
from killchain.report import render_report
from killchain.review import build_review
from killchain.rules import load_rules

router = APIRouter(prefix="/api", tags=["Kill Chain"])

# run_id becomes a directory name and part of DuckDB file paths: allow-list it.
RunId = Annotated[str, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
DEFAULT_RUN = get_settings().KILLCHAIN_RUN_ID

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
def list_incidents(run_id: RunId = DEFAULT_RUN, limit: int = Query(100, ge=1, le=1000),
                   min_risk: float = 0.0) -> list[dict]:
    rows = [{k: inc.get(k) for k in _SUMMARY_KEYS} for inc in load_run(_run_dir(run_id)).values()
            if inc.get("risk_score", 0) >= min_risk]
    rows.sort(key=lambda r: (-r["risk_score"], r["first_seen"]))
    return rows[:limit]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, run_id: RunId = DEFAULT_RUN) -> dict:
    return _incident(incident_id, run_id)


@router.get("/incidents/{incident_id}/path")
def get_incident_path(incident_id: int, run_id: RunId = DEFAULT_RUN) -> dict:
    inc = _incident(incident_id, run_id)
    return {"incident_id": incident_id, "title": inc["title"], "timeline": inc["timeline"],
            "path": inc["path"]}


@router.get("/incidents/{incident_id}/next")
def get_incident_next(incident_id: int, run_id: RunId = DEFAULT_RUN) -> dict:
    return _incident(incident_id, run_id)["reach"]


@router.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: int, run_id: RunId = DEFAULT_RUN, llm: bool = False) -> dict:
    inc = _incident(incident_id, run_id)
    if not llm:
        return inc["report"]
    model = Incident.model_validate({k: v for k, v in inc.items() if k in Incident.model_fields})
    return render_report(model, [TimelineStep(**s) for s in inc["timeline"]],
                         ReachResult(**inc["reach"]), use_llm=True)


@router.get("/incidents/{incident_id}/review")
def get_incident_review(incident_id: int, run_id: RunId = DEFAULT_RUN, llm: bool = False) -> dict:
    inc = _incident(incident_id, run_id)
    return build_review(inc, _run_dir(run_id), use_llm=True) if llm else inc["review"]


class ResponseTransition(BaseModel):
    action_id: str = Field(max_length=300)
    to_status: str
    note: str = Field(default="", max_length=500)


@router.get("/response/actions")
def get_response_actions(run_id: RunId = DEFAULT_RUN) -> list[dict]:
    return response.all_actions(load_run(_run_dir(run_id)), _run_dir(run_id))


@router.post("/response/transition")
def post_response_transition(body: ResponseTransition, run_id: RunId = DEFAULT_RUN) -> dict:
    run_dir = _run_dir(run_id)
    known = {a["action_id"] for a in response.all_actions(load_run(run_dir), run_dir)}
    try:
        status = response.transition(run_dir, body.action_id, body.to_status, known, note=body.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown action") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"action_id": body.action_id, "status": status}


@router.post("/response/export", response_class=PlainTextResponse)
def post_response_export(run_id: RunId = DEFAULT_RUN) -> str:
    return response.export_script(load_run(_run_dir(run_id)), _run_dir(run_id))


@router.get("/response/audit")
def get_response_audit(run_id: RunId = DEFAULT_RUN) -> list[dict]:
    return response.read_audit(_run_dir(run_id))


@router.get("/killchain/compliance")
def get_compliance(run_id: RunId = DEFAULT_RUN) -> dict:
    controls = load_controls(Path(get_settings().KILLCHAIN_CONTROLS_PATH))
    return evaluate_controls(load_run(_run_dir(run_id)), controls)


@router.get("/anomalies")
def list_anomalies(run_id: RunId = DEFAULT_RUN, limit: int = Query(50, ge=1, le=500),
                   offset: int = Query(0, ge=0), kind: str = "", q: str = "",
                   notable_only: bool = True) -> dict:
    rows = load_anomalies(_run_dir(run_id))
    all_total = len(rows)
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    if q:
        needle = q.strip().lower()
        rows = [r for r in rows if needle in r["entity"].lower()]
    if notable_only:
        # A lead where every reason is "unusually far BELOW the peer median" is a quiet
        # entity, not a sign of attack activity: hide it unless the user asks to see it.
        rows = [r for r in rows if any("above the peer median" in reason for reason in r["reasons"])]
    return {"total": len(rows), "all_total": all_total, "items": rows[offset:offset + limit]}


@router.get("/accounts")
def list_accounts(run_id: RunId = DEFAULT_RUN) -> list[dict]:
    return load_accounts(_run_dir(run_id))


@router.get("/killchain/llm-safety")
def get_llm_safety(run_id: RunId = DEFAULT_RUN) -> dict:
    incidents = load_run(_run_dir(run_id)).values()
    flagged = [{"incident_id": i["incident_id"], "evidence": i["review"]["injection_flags"]}
               for i in incidents if i.get("review", {}).get("injection_flags")]
    return {"incidents_scanned": len(incidents),
            "evidence_items_scanned": sum(len(i.get("review", {}).get("evidence", [])) for i in incidents),
            "incidents_with_suspected_injection": flagged}


@router.get("/actors")
def list_actors(run_id: RunId = DEFAULT_RUN) -> list[dict]:
    return load_actors(_run_dir(run_id))


@router.get("/killchain/rules")
def get_rules() -> list[dict]:
    return [{"id": r.id, "title": r.title, "technique": r.technique, "kind": r.kind,
             "severity": r.severity, "where": r.where, "selection": r.selection}
            for r in load_rules(Path(get_settings().KILLCHAIN_RULES_DIR))]


@router.get("/killchain/status")
def get_status(run_id: RunId = DEFAULT_RUN) -> dict:
    meta = load_meta(_run_dir(run_id))
    status = _state["status"]
    if status == "idle" and meta:
        status = "complete"
    return {**_state, "status": status, "run_meta": meta}


@router.post("/killchain/run")
def start_run(run_id: RunId = DEFAULT_RUN, skip_ingest: bool = True) -> dict:
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
