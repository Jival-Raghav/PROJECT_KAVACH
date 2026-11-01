"""Live mode picks the same parser the batch pipeline would: FortiGate, or a learned schema."""
import json

import pytest

from killchain.live import LiveJob, read_state
from killchain.onboard import choose_parser, load_schema
from killchain.pipeline import load_meta, load_run, run_killchain
from tests.kc_fixture import REPO, write_log
from tests.kc_vendor import to_acme
from tests.test_kc_onboard import GOOD, VALS, _llm
from tests.test_kc_onboard import _lines as vendor_kv_lines
from tests.test_kc_pipeline_eval import RULES, _lines

ACME_SCHEMA = REPO / "config/log_sources/acme_ngfw.yaml"


def _no_llm(_messages):
    raise AssertionError("the LLM must not be called")


@pytest.fixture
def kc(tmp_path, monkeypatch):
    from config import get_settings

    monkeypatch.setattr(get_settings(), "KILLCHAIN_DATA_DIR", str(tmp_path / "kc"))
    monkeypatch.setattr(get_settings(), "LLM_REPLAY_ONLY", False)
    monkeypatch.setattr("killchain.onboard.time.sleep", lambda _s: None)
    return tmp_path


def _fortigate_log(tmp_path):
    return write_log(tmp_path / "fortigate.log", _lines())


def _acme_log(tmp_path):
    return write_log(tmp_path / "acme.jsonl", [to_acme(line) for line in _lines()])


def _summary(run_dir):
    """What the incidents found, independent of timestamps' sub-second precision."""
    return sorted((inc["title"], tuple(sorted(d["technique"]["id"] for d in inc["detections"])))
                  for inc in load_run(run_dir).values())


def _live(tmp_path, log, run_id, **kw):
    job = LiveJob(tmp_path / "kc/runs" / run_id, log, RULES, batch_size=40, poll_seconds=0.01,
                  **kw)
    return job, job.run()


def test_parser_is_chosen_automatically_for_each_format(kc):
    assert choose_parser(_fortigate_log(kc), llm=_no_llm) is None
    assert choose_parser(_acme_log(kc), llm=_no_llm) == ACME_SCHEMA


def test_batch_run_reads_acme_through_the_schema_and_finds_the_same_attacks(kc):
    run_killchain(_fortigate_log(kc), kc / "fg", RULES)
    meta = run_killchain(_acme_log(kc), kc / "acme", RULES)
    assert meta["source_schema"] == str(ACME_SCHEMA) and meta["schema_reviewed"] is True
    assert _summary(kc / "acme") == _summary(kc / "fg") and len(_summary(kc / "fg")) == 2


def test_live_fortigate_uses_the_standard_parser(kc):
    job, state = _live(kc, _fortigate_log(kc), "live-fg", llm=_no_llm)
    assert state["status"] == "complete" and state["parser"] == "fortigate"
    assert state["schema_path"] is None
    assert "source_schema" not in load_meta(job.run_dir)
    assert len(load_run(job.run_dir)) == 2


def test_live_acme_uses_the_saved_schema_and_matches_batch(kc):
    log = _acme_log(kc)
    run_killchain(log, kc / "acme-batch", RULES)
    job, state = _live(kc, log, "live-acme", llm=_no_llm)
    assert state["status"] == "complete" and state["parser"] == "schema"
    assert state["schema_path"] == str(ACME_SCHEMA) and state["generation"] >= 1
    meta = load_meta(job.run_dir)
    assert meta["schema_reviewed"] is True and meta["rule_coverage"]["rules_total"] > 0
    assert _summary(job.run_dir) == _summary(kc / "acme-batch")


def test_explicit_schema_overrides_the_automatic_choice(kc):
    job, state = _live(kc, _acme_log(kc), "live-explicit", schema_path=ACME_SCHEMA,
                       llm=_no_llm)
    assert state["parser"] == "schema" and state["schema_path"] == str(ACME_SCHEMA)
    assert len(load_run(job.run_dir)) == 2


def test_live_learns_a_new_format_once_and_reports_it_unreviewed(kc):
    log = write_log(kc / "vendor.log", vendor_kv_lines())
    llm = _llm(GOOD, VALS)
    job, state = _live(kc, log, "live-learned", llm=llm)
    assert state["status"] == "complete" and state["parser"] == "schema" and llm.calls
    learned = load_schema(state["schema_path"])
    assert learned["approved"] == "auto"
    assert load_meta(job.run_dir)["schema_reviewed"] is False
    parsed = state["lines_parsed"]
    assert parsed == len(vendor_kv_lines())


def test_resume_reuses_the_chosen_parser_without_relearning(kc):
    log = write_log(kc / "vendor.log", vendor_kv_lines())
    run_dir = kc / "kc/runs/live-resume"
    first = LiveJob(run_dir, log, RULES, batch_size=40, poll_seconds=0.01, llm=_llm(GOOD, VALS),
                    on_cycle=lambda _e: first.stop())
    assert first.run()["status"] == "stopped"
    chosen = read_state(run_dir)["schema_path"]
    again = LiveJob(run_dir, log, RULES, batch_size=40, poll_seconds=0.01, llm=_no_llm)
    state = again.run()
    assert state["status"] == "complete" and state["schema_path"] == chosen
    assert state["lines_parsed"] == len(vendor_kv_lines())


def test_new_format_with_the_llm_off_fails_with_a_clear_message(kc, monkeypatch):
    from config import get_settings

    monkeypatch.setattr(get_settings(), "LLM_REPLAY_ONLY", True)
    log = write_log(kc / "vendor.log", vendor_kv_lines())
    job = LiveJob(kc / "kc/runs/live-off", log, RULES, batch_size=40, poll_seconds=0.01)
    with pytest.raises(ValueError, match="LLM_REPLAY_ONLY"):
        job.run()
    state = read_state(job.run_dir)
    assert state["status"] == "error" and "LLM_REPLAY_ONLY" in state["error"]


def test_api_rejects_a_missing_schema(kc):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.live import router

    app = FastAPI()
    app.include_router(router)
    body = {"path": str(_acme_log(kc)), "run_id": "x1", "schema_path": str(kc / "nope.yaml")}
    r = TestClient(app).post("/api/live/start", json=body)
    assert r.status_code == 400 and "Schema not found" in r.json()["detail"]
    assert not (kc / "kc/runs/x1").exists()


def test_acme_lines_are_json_not_fortigate(kc):
    line = json.loads(to_acme(_lines()[0]))
    assert line["verdict"] == "drop" and line["zone_in"] == "outside" and "srcintfrole" not in line
