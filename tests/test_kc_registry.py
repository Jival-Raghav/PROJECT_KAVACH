import json

from tests.kc_fixture import REPO, write_log
from tests.test_kc_correlate import det
from tests.test_kc_pipeline_eval import _lines
from killchain.models import Incident
from killchain.pipeline import analyse_run, run_killchain
from killchain.registry import load_registry, renumber, resolve, save_registry

RULES = REPO / "config/detection_rules"


def inc(*dets):
    return Incident(incident_id=0, title="t", detections=list(dets),
                    first_seen=min(d.first_seen for d in dets),
                    last_seen=max(d.last_seen for d in dets))


def A():
    return det("A:1", "T1190", 0, src_ip="1.1.1.1")


def B():
    return det("B:1", "T1190", 1, src_ip="2.2.2.2")


def C():
    return det("C:1", "T1190", 2, src_ip="3.3.3.3")


def test_first_cycle_numbers_from_one():
    reg = {"next": 1, "numbers": {}}
    incs = [inc(A()), inc(B()), inc(C())]
    r = renumber(incs, reg)
    assert {i.incident_id for i in incs} == {1, 2, 3}
    assert r["new"] == [1, 2, 3]


def test_missing_file_gives_empty_registry(tmp_path):
    assert load_registry(tmp_path / "nope.json") == {"next": 1, "numbers": {}}
    reg = {"next": 2, "numbers": {"1": {"status": "active", "detections": ["A:1"],
                                        "merged_into": None}}}
    save_registry(tmp_path / "r.json", reg)
    assert load_registry(tmp_path / "r.json") == reg


def test_number_kept_when_earlier_detection_joins():
    reg = {"next": 1, "numbers": {}}
    renumber([inc(B())], reg)
    i2 = inc(A(), B())
    r = renumber([i2], reg)
    assert i2.incident_id == 1 and r["new"] == []


def test_merge_keeps_lower_number():
    reg = {"next": 1, "numbers": {}}
    renumber([inc(A()), inc(B())], reg)
    nums = {d: n for n, e in reg["numbers"].items() for d in e["detections"]}
    assert nums == {"A:1": "1", "B:1": "2"}
    i = inc(A(), B())
    r = renumber([i], reg)
    assert i.incident_id == 1
    assert r["merged"] == {2: 1}
    assert resolve(reg, 2) == {"merged_into": 1}
    assert resolve(reg, 1) is None


def test_withdrawn_number():
    reg = {"next": 1, "numbers": {}}
    renumber([inc(A()), inc(B())], reg)
    i = inc(B())
    r = renumber([i], reg)
    assert i.incident_id == 2
    assert r["withdrawn"] == [1]
    assert resolve(reg, 1) == {"withdrawn": True}


def test_split_largest_overlap_keeps_number():
    reg = {"next": 1, "numbers": {}}
    renumber([inc(A(), B(), C())], reg)
    ab, c = inc(A(), B()), inc(C())
    renumber([ab, c], reg)
    assert ab.incident_id == 1 and c.incident_id == 2


def test_resolve_follows_chain():
    reg = {"next": 4, "numbers": {
        "1": {"status": "active", "detections": ["A:1"], "merged_into": None},
        "2": {"status": "merged", "detections": [], "merged_into": 1},
        "3": {"status": "merged", "detections": [], "merged_into": 2}}}
    assert resolve(reg, 3) == {"merged_into": 1}
    assert resolve(reg, 99) is None


def test_analyse_run_without_registry_keeps_batch_numbering(tmp_path):
    log = write_log(tmp_path / "f.log", _lines())
    run_dir = tmp_path / "run"
    run_killchain(log, run_dir, RULES)
    meta = analyse_run(run_dir, RULES)
    assert "renumber" not in meta
    ids = [i["incident_id"] for i in json.loads((run_dir / "incidents.json").read_text())]
    assert sorted(ids) == [1, 2]


def test_analyse_run_with_registry_records_renumber(tmp_path):
    log = write_log(tmp_path / "f.log", _lines())
    run_dir = tmp_path / "run"
    run_killchain(log, run_dir, RULES)
    reg_path = tmp_path / "registry.json"
    meta = analyse_run(run_dir, RULES, registry_path=reg_path)
    assert meta["renumber"]["new"] == [1, 2] or sorted(meta["renumber"]["new"]) == [1, 2]
    again = analyse_run(run_dir, RULES, registry_path=reg_path)
    assert again["renumber"] == {"new": [], "merged": {}, "withdrawn": []}
    assert reg_path.exists()
