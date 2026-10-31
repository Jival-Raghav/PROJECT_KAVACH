import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.kc_fixture import write_log
from tests.test_kc_pipeline_eval import RULES, _lines
from killchain.pipeline import clear_cache, run_killchain


@pytest.fixture
def client(tmp_path, monkeypatch):
    from config import get_settings
    from api.incidents import router

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    clear_cache()
    app = FastAPI()
    app.include_router(router)
    return TestClient(app), tmp_path / "kc" / "runs" / "firex"


def _populate(run_dir, tmp_path):
    run_killchain(write_log(tmp_path / "f.log", _lines()), run_dir, RULES)


def test_no_run_returns_empty_list(client):
    c, _ = client
    r = c.get("/api/incidents")
    assert r.status_code == 200 and r.json() == []


def test_list_sorted_by_risk(client, tmp_path):
    c, run_dir = client
    _populate(run_dir, tmp_path)
    rows = c.get("/api/incidents").json()
    assert len(rows) == 2
    assert [r["risk_score"] for r in rows] == sorted((r["risk_score"] for r in rows), reverse=True)
    assert {"incident_id", "title", "severity", "raw_alert_count", "detection_count", "stages",
            "tactics", "first_seen", "last_seen"} <= set(rows[0])
    assert "timeline" not in rows[0]
    assert len(c.get("/api/incidents?min_risk=101").json()) == 0


def test_path_endpoint_shape(client, tmp_path):
    c, run_dir = client
    _populate(run_dir, tmp_path)
    body = c.get("/api/incidents/1/path").json()
    assert {"timeline", "path"} <= set(body)
    assert body["path"]["nodes"] and body["path"]["edges"]


def test_next_and_report_endpoints(client, tmp_path):
    c, run_dir = client
    _populate(run_dir, tmp_path)
    assert "summary" in c.get("/api/incidents/1/next").json()
    rep = c.get("/api/incidents/1/report").json()
    assert rep["generated_by"] == "template" and rep["body_markdown"].startswith("# Incident")
    assert c.get("/api/incidents/1").json()["incident_id"] == 1


def test_unknown_incident_404(client, tmp_path):
    c, run_dir = client
    _populate(run_dir, tmp_path)
    for suffix in ("", "/path", "/next", "/report"):
        assert c.get(f"/api/incidents/999{suffix}").status_code == 404


def test_open_latency(client, tmp_path):
    c, run_dir = client
    _populate(run_dir, tmp_path)
    c.get("/api/incidents/1/path")
    t = time.perf_counter()
    assert c.get("/api/incidents/1/path").status_code == 200
    assert (time.perf_counter() - t) < 0.5


def test_rules_and_status(client):
    c, _ = client
    rules = c.get("/api/killchain/rules").json()
    assert len(rules) >= 18 and {"id", "title", "technique", "kind", "severity"} <= set(rules[0])
    assert c.get("/api/killchain/status").json()["status"] in ("idle", "complete")


def test_main_app_mounts_router():
    from main import app

    paths = set(app.openapi()["paths"])
    assert "/api/incidents/{incident_id}/path" in paths
