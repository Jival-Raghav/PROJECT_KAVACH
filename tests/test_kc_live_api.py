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
    out = capsys.readouterr().out
    assert "[live] gen " in out and "[live] complete: " in out


@pytest.mark.parametrize("run_id,path,msg", [
    ("firex", "LOG", "The firex run cannot be used for live mode"),
    ("../x", "LOG", "Invalid run id"),
    ("ok1", "MISSING", "File not found"),
])
def test_cli_live_validates_before_touching_disk(tmp_path, monkeypatch, run_id, path, msg):
    from config import get_settings
    from killchain.cli import main

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    log = write_log(tmp_path / "f.log", _lines())
    p = str(log) if path == "LOG" else str(tmp_path / "nope.log")
    with pytest.raises(SystemExit) as ei:
        main(["live", "--path", p, "--run-id", run_id])
    assert msg in str(ei.value)
    assert not (tmp_path / "kc").exists() and not (tmp_path / "x").exists()


def test_cli_live_ctrl_c_stops_cleanly(tmp_path, monkeypatch, capsys):
    from config import get_settings
    from killchain.cli import main
    from killchain.live import LiveJob, read_state

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    monkeypatch.setattr(get_settings(), "KILLCHAIN_RULES_DIR", str(RULES))
    log = write_log(tmp_path / "f.log", _lines())
    real_join = LiveJob.join
    calls = {"n": 0}

    def join(self, timeout=None):
        if timeout is not None and calls["n"] == 0:
            calls["n"] += 1
            raise KeyboardInterrupt
        return real_join(self, timeout)

    monkeypatch.setattr(LiveJob, "join", join)
    with pytest.raises(SystemExit) as ei:
        main(["live", "--path", str(log), "--run-id", "k1", "--batch-size", "40"])
    assert ei.value.code != 0
    assert "resume with the same --run-id" in capsys.readouterr().out
    assert read_state(tmp_path / "kc" / "runs" / "k1")["status"] in ("stopped", "complete")


def _junk(path, n=100_001):
    path.write_text("not a fortigate line\n" * n, encoding="utf-8")
    return path


def _zip(tmp_path):
    import zipfile

    log = write_log(tmp_path / "f.log", _lines())
    z = tmp_path / "f.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(log, "f.log")
    return z


def _owned_state(runs, run_id, log, pid, beat):
    from killchain.live import new_state, save_state

    st = new_state(log)
    st.update(owner_pid=pid, heartbeat_at=beat)
    save_state(runs / run_id, st)


def _dead_pid():
    import subprocess
    import sys

    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def test_run_owned_by_another_live_process_is_processing_and_not_restartable(client, tmp_path):
    import os
    from datetime import UTC, datetime

    c, runs = client
    log = write_log(tmp_path / "f.log", _lines())
    _owned_state(runs, "o1", log, os.getpid(), datetime.now(UTC).isoformat())
    assert c.get("/api/live/status?run_id=o1").json()["status"] == "processing"
    assert {x["run_id"]: x["status"] for x in c.get("/api/runs").json()}["o1"] == "processing"
    r = c.post("/api/live/start", json={"path": str(log), "run_id": "o1"})
    assert r.status_code == 409
    assert r.json()["detail"] == "Run o1 is being processed by another process"


@pytest.mark.parametrize("owner", ["dead_pid", "stale_heartbeat"])
def test_run_with_gone_owner_is_interrupted(client, tmp_path, owner):
    import os
    from datetime import UTC, datetime, timedelta

    c, runs = client
    log = write_log(tmp_path / "f.log", _lines())
    now = datetime.now(UTC)
    if owner == "dead_pid":
        _owned_state(runs, "g1", log, _dead_pid(), now.isoformat())
    else:
        _owned_state(runs, "g1", log, os.getpid(), (now - timedelta(seconds=61)).isoformat())
    assert c.get("/api/live/status?run_id=g1").json()["status"] == "interrupted"
    assert {x["run_id"]: x["status"] for x in c.get("/api/runs").json()}["g1"] == "interrupted"


def test_start_writes_owned_state_before_returning(client, tmp_path, monkeypatch):
    import os

    from killchain.live import LiveJob, read_state

    c, runs = client
    gate = threading.Event()
    monkeypatch.setattr(LiveJob, "run", lambda self: gate.wait(10) or {})
    log = write_log(tmp_path / "f.log", _lines())
    try:
        assert c.post("/api/live/start", json={"path": str(log), "run_id": "s1"}).status_code == 200
        st = read_state(runs / "s1")
        assert st["status"] == "processing" and st["owner_pid"] == os.getpid()
        assert st["heartbeat_at"]
        listed = {x["run_id"]: x for x in c.get("/api/runs").json()}
        assert listed["s1"]["kind"] == "live" and listed["s1"]["status"] == "processing"
    finally:
        gate.set()


def test_batch_rerun_refuses_live_run(client):
    c, runs = client
    (runs / "lv").mkdir(parents=True)
    (runs / "lv" / "live_state.json").write_text(
        json.dumps({"path": "/x", "status": "stopped"}), encoding="utf-8")
    r = c.post("/api/killchain/run?run_id=lv")
    assert r.status_code == 409 and r.json()["detail"] == "Run lv is a live run"


def test_start_rejects_zip(client, tmp_path):
    c, runs = client
    z = _zip(tmp_path)
    r = c.post("/api/live/start", json={"path": str(z), "run_id": "z1"})
    assert r.status_code == 400
    assert r.json()["detail"] == f"Zip archives are not supported: {z}"
    assert not (runs / "z1").exists()


def test_start_refuses_batch_run(client, tmp_path):
    c, runs = client
    (runs / "b1").mkdir(parents=True)
    (runs / "b1" / "run_meta.json").write_text("{}", encoding="utf-8")
    log = write_log(tmp_path / "f.log", _lines())
    r = c.post("/api/live/start", json={"path": str(log), "run_id": "b1"})
    assert r.status_code == 400
    assert r.json()["detail"] == "Run b1 is a batch run and cannot be used for live mode"
    assert sorted(p.name for p in (runs / "b1").iterdir()) == ["run_meta.json"]


def test_junk_file_ends_in_error(client, tmp_path):
    c, _ = client
    junk = _junk(tmp_path / "junk.log")
    assert c.post("/api/live/start", json={"path": str(junk), "run_id": "j1"}).status_code == 200
    assert _wait_status(c, "j1", "error", timeout=60) == "error"
    st = c.get("/api/live/status?run_id=j1").json()
    # Rejected up front by the parser chooser, as the batch pipeline would; the reader's own
    # 100,000-line guard is tested in test_kc_live_stream.
    assert st["error"] == "Could not recognise this log as key=value, JSON or CSV."
    assert st["generation"] == 0


def test_cli_live_rejects_zip_and_batch_run(tmp_path, monkeypatch):
    from config import get_settings
    from killchain.cli import main

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    z = _zip(tmp_path)
    with pytest.raises(SystemExit) as ei:
        main(["live", "--path", str(z), "--run-id", "z1"])
    assert str(ei.value) == f"Zip archives are not supported: {z}"
    assert not (tmp_path / "kc").exists()

    b = tmp_path / "kc" / "runs" / "b1"
    b.mkdir(parents=True)
    (b / "run_meta.json").write_text("{}", encoding="utf-8")
    log = write_log(tmp_path / "f.log", _lines())
    with pytest.raises(SystemExit) as ei:
        main(["live", "--path", str(log), "--run-id", "b1"])
    assert str(ei.value) == "Run b1 is a batch run and cannot be used for live mode"
    assert sorted(p.name for p in b.iterdir()) == ["run_meta.json"]


def test_cli_live_junk_file_exits_with_error(tmp_path, monkeypatch):
    from config import get_settings
    from killchain.cli import main

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    monkeypatch.setattr(get_settings(), "KILLCHAIN_RULES_DIR", str(RULES))
    junk = _junk(tmp_path / "junk.log")
    with pytest.raises(SystemExit) as ei:
        main(["live", "--path", str(junk), "--run-id", "j2"])
    assert ei.value.code != 0
    assert str(ei.value) == ("[live] error: Could not recognise this log as key=value, "
                             "JSON or CSV.")


def test_cli_live_refuses_run_owned_elsewhere(tmp_path, monkeypatch):
    import os
    from datetime import UTC, datetime

    from config import get_settings
    from killchain.cli import main

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    log = write_log(tmp_path / "f.log", _lines())
    _owned_state(tmp_path / "kc" / "runs", "o2", log, os.getpid(), datetime.now(UTC).isoformat())
    with pytest.raises(SystemExit) as ei:
        main(["live", "--path", str(log), "--run-id", "o2"])
    assert str(ei.value) == "Run o2 is being processed by another process"
