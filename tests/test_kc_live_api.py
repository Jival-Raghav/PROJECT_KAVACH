import json
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.kc_fixture import write_log
from tests.test_kc_pipeline_eval import RULES, _lines
from killchain.pipeline import clear_cache


@pytest.fixture
def client(tmp_path, monkeypatch):
    from config import get_settings
    from api import live
    from api.incidents import router as inc_router

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    monkeypatch.setattr(get_settings(), "KILLCHAIN_RULES_DIR", str(RULES))
    clear_cache()
    app = FastAPI()
    app.include_router(inc_router)
    app.include_router(live.router)
    yield TestClient(app), tmp_path / "kc" / "runs"
    with live._jobs_lock:
        jobs = list(live._jobs.values())
        live._jobs.clear()
    for j in jobs:
        j.stop()
        j.join(10)


def _wait_status(c, run_id, want, timeout=15):
    deadline = time.time() + timeout
    st = None
    while time.time() < deadline:
        r = c.get(f"/api/live/status?run_id={run_id}")
        st = r.json().get("status") if r.status_code == 200 else None
        if st == want:
            return st
        time.sleep(0.05)
    return st


def test_start_rejects_bad_paths(client, tmp_path):
    c, runs = client
    missing = str(tmp_path / "nope.log")
    r = c.post("/api/live/start", json={"path": missing, "run_id": "x1"})
    assert r.status_code == 400 and r.json()["detail"] == f"File not found: {missing}"
    r = c.post("/api/live/start", json={"path": str(tmp_path), "run_id": "x1"})
    assert r.status_code == 400 and r.json()["detail"] == f"File not found: {tmp_path}"
    r = c.post("/api/live/start", json={"path": "", "run_id": "x1"})
    assert r.status_code == 400 and r.json()["detail"] == "File not found: "
    log = write_log(tmp_path / "f.log", _lines())
    r = c.post("/api/live/start", json={"path": str(log), "run_id": "firex"})
    assert r.status_code == 400
    assert r.json()["detail"] == "The firex run cannot be used for live mode"
    assert not runs.exists() or list(runs.iterdir()) == []


def test_start_runs_to_complete_and_serves_incidents(client, tmp_path):
    c, runs = client
    log = write_log(tmp_path / "f.log", _lines())
    r = c.post("/api/live/start", json={"path": str(log), "run_id": "t1"})
    assert r.status_code == 200 and r.json() == {"run_id": "t1", "status": "processing"}
    assert _wait_status(c, "t1", "complete") == "complete"
    assert c.get("/api/incidents?run_id=t1").json()
    listed = {x["run_id"]: x for x in c.get("/api/runs").json()}
    assert listed["t1"]["kind"] == "live" and listed["t1"]["path"] == str(log.resolve())
    assert c.get("/api/live/changes?run_id=t1").json()
    assert c.get("/api/live/changes?run_id=t1&since_generation=9999").json() == []
    assert c.get("/api/incidents?run_id=firex").json() == []
    assert not (runs / "firex").exists()


def test_second_start_while_running_is_409(client, tmp_path, monkeypatch):
    from killchain.live import LiveJob

    c, _ = client
    gate = threading.Event()
    monkeypatch.setattr(LiveJob, "run", lambda self: gate.wait(10) or {})
    log = write_log(tmp_path / "f.log", _lines())
    try:
        assert c.post("/api/live/start", json={"path": str(log), "run_id": "a1"}).status_code == 200
        r = c.post("/api/live/start", json={"path": str(log), "run_id": "a2"})
        assert r.status_code == 409
        assert c.post("/api/live/stop?run_id=a1").json() == {"status": "stopping"}
        assert c.post("/api/live/stop?run_id=zzz").status_code == 404
    finally:
        gate.set()


def test_status_reports_interrupted_without_job(client):
    c, runs = client
    (runs / "r9").mkdir(parents=True)
    (runs / "r9" / "live_state.json").write_text(
        json.dumps({"path": "/x", "status": "processing"}), encoding="utf-8")
    assert c.get("/api/live/status?run_id=r9").json()["status"] == "interrupted"
    assert c.get("/api/live/status?run_id=nothere").status_code == 404


def test_merged_and_withdrawn_ids_return_detail(client):
    c, runs = client
    d = runs / "m1"
    d.mkdir(parents=True)
    reg = {"next": 4, "numbers": {
        "1": {"status": "active", "detections": [], "merged_into": None},
        "2": {"status": "merged", "detections": [], "merged_into": 1},
        "3": {"status": "withdrawn", "detections": [], "merged_into": None}}}
    (d / "incident_registry.json").write_text(json.dumps(reg), encoding="utf-8")
    (d / "incidents.json").write_text(json.dumps([{"incident_id": 1}]), encoding="utf-8")
    r = c.get("/api/incidents/2?run_id=m1")
    assert r.status_code == 404 and r.json()["detail"] == {"merged_into": 1}
    r = c.get("/api/incidents/3?run_id=m1")
    assert r.status_code == 404 and r.json()["detail"] == {"withdrawn": True}
    r = c.get("/api/incidents/77?run_id=m1")
    assert r.status_code == 404 and r.json()["detail"] == "Incident 77 not found"


def test_cli_live_runs_to_completion(tmp_path, monkeypatch, capsys):
    from config import get_settings
    from killchain.cli import main
    from killchain.live import read_state

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    monkeypatch.setattr(get_settings(), "KILLCHAIN_RULES_DIR", str(RULES))
    log = write_log(tmp_path / "f.log", _lines())
    main(["live", "--path", str(log), "--run-id", "c1", "--batch-size", "40"])
    assert read_state(tmp_path / "kc" / "runs" / "c1")["status"] == "complete"
    assert "[live] gen " in capsys.readouterr().out
