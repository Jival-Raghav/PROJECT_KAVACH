import json
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
    return TestClient(app), tmp_path / "kc" / "runs" / get_settings().KILLCHAIN_RUN_ID


def _populate(run_dir, tmp_path):
    run_killchain(write_log(tmp_path / "f.log", _lines()), run_dir, RULES)


def test_no_run_returns_empty_list(client):
    c, _ = client
    r = c.get("/api/incidents")
    assert r.status_code == 200 and r.json() == []


def test_review_endpoint_works_with_and_without_llm(client, tmp_path, monkeypatch):
    from config import get_settings

    c, run_dir = client
    _populate(run_dir, tmp_path)
    monkeypatch.setattr(get_settings(), "LLM_REPLAY_ONLY", True)
    for url in ("/api/incidents/1/review", "/api/incidents/1/review?llm=true"):
        body = c.get(url).json()
        assert body["generated_by"] == "template" and body["prosecution"] and body["verdict"]
    assert c.get("/api/incidents/999/review").status_code == 404


def test_response_approval_and_export_flow(client, tmp_path):
    c, run_dir = client
    _populate(run_dir, tmp_path)
    action = c.get("/api/response/actions").json()[0]
    assert action["status"] == "proposed"
    assert c.post("/api/response/export").text.count("set subnet") == 0
    body = {"action_id": action["action_id"], "to_status": "approved"}
    assert c.post("/api/response/transition", json=body).json()["status"] == "approved"
    assert c.post("/api/response/transition", json=body).status_code == 409
    missing = {"action_id": "block_ip:0.0.0.0", "to_status": "approved"}
    assert c.post("/api/response/transition", json=missing).status_code == 404
    assert "DRY RUN" in c.post("/api/response/export").text
    assert [e["to"] for e in c.get("/api/response/audit").json()] == ["approved", "exported"]


def test_compliance_endpoint(client, tmp_path):
    c, run_dir = client
    assert c.get("/api/killchain/compliance").json()["counts"]["gap"] == 0
    _populate(run_dir, tmp_path)
    body = c.get("/api/killchain/compliance").json()
    assert sum(body["counts"].values()) == len(body["controls"]) and body["notice"]


def test_anomalies_empty_without_a_run(client):
    c, _ = client
    res = c.get("/api/anomalies").json()
    assert res["total"] == 0 and res["items"] == []


def test_anomalies_are_paged(client):
    c, run_dir = client
    run_dir.mkdir(parents=True)
    rows = [{"entity": f"e{i}", "kind": "user", "score": 90 - i, "reasons": ["above the peer median"]} for i in range(5)]
    (run_dir / "anomalies.json").write_text(json.dumps(rows), encoding="utf-8")
    page = c.get("/api/anomalies?limit=2&offset=2").json()
    assert page["total"] == 5 and [r["entity"] for r in page["items"]] == ["e2", "e3"]


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


def test_run_id_is_validated(client):
    c, _ = client
    assert c.get("/api/incidents?run_id=../../etc").status_code == 422
    assert c.get("/api/incidents/1/path?run_id=a'b").status_code == 422
    assert c.post("/api/killchain/run?run_id=../x").status_code == 422
