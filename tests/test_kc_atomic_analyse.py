import json

from tests.kc_fixture import fg_line, write_log
from killchain.atomic import write_json_atomic
from killchain.ingest import ingest_log
from killchain.pipeline import analyse_run, run_killchain
from killchain.store import list_parts, open_events
from tests.test_kc_pipeline_eval import RULES, _lines


def test_write_json_atomic_replaces_and_leaves_no_tmp(tmp_path):
    p = tmp_path / "x.json"
    write_json_atomic(p, {"a": 1})
    write_json_atomic(p, {"a": 2})
    assert json.loads(p.read_text()) == {"a": 2}
    assert [f.name for f in tmp_path.iterdir()] == ["x.json"]


def test_open_events_reads_only_given_parts(tmp_path):
    lines = [fg_line(srcip=f"10.10.10.{i}") for i in range(25)]
    ingest_log(write_log(tmp_path / "f.log", lines), tmp_path / "run", batch_size=10)
    parts = list_parts(tmp_path / "run")
    assert len(parts) == 3
    con = open_events(tmp_path / "run", parts=parts[:1])
    assert con.execute("select count(*) from events_all").fetchone()[0] == 10


def test_analyse_run_matches_run_killchain(tmp_path):
    log = write_log(tmp_path / "f.log", _lines())
    run_killchain(log, tmp_path / "a", RULES)
    ingest_log(log, tmp_path / "b")
    analyse_run(tmp_path / "b", RULES)
    a = json.loads((tmp_path / "a/incidents.json").read_text())
    b = json.loads((tmp_path / "b/incidents.json").read_text())
    assert [(i["incident_id"], i["title"], i["risk_score"]) for i in a] == \
           [(i["incident_id"], i["title"], i["risk_score"]) for i in b]
    assert not list((tmp_path / "b").glob("*.tmp")) and not list((tmp_path / "b").glob(".*.tmp"))
