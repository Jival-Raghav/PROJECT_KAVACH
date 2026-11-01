import json

import pytest

from tests.kc_fixture import REPO, at, fg_line, write_log
from killchain.evaluate import evaluate
from killchain.pipeline import load_run, run_killchain

RULES = REPO / "config/detection_rules"

GT = """
scenarios:
  - id: S1
    name: scan
    steps:
      - {id: S1-1, techniques: [T1595], where: "srcip='9.9.9.9'", expected_count: 120}
  - id: S2
    name: sqli then webshell
    steps:
      - {id: S2-1, techniques: [T1190], where: "srcip='8.8.4.4' AND subtype='ips'", expected_count: 12}
      - {id: S2-2, techniques: [T1505.003], where: "srcip='8.8.4.4' AND subtype='webfilter'", expected_count: 6}
"""


def _lines(extra=()):
    scan = [fg_line(at(i * 0.01), action="deny", srcip="9.9.9.9", srcintfrole="wan",
                    dstip="10.10.20.5", dstintfrole="dmz", dstport=p)
            for i, p in enumerate(range(1, 121))]
    sqli = [fg_line(at(100 + i * 0.3), type="utm", subtype="ips", action="dropped",
                    attack="HTTP.URI.SQL.Injection", srcip="8.8.4.4", srcintfrole="wan",
                    dstip="10.10.20.20", dstintfrole="dmz") for i in range(12)]
    shell = [fg_line(at(130 + i), type="utm", subtype="webfilter", action="passthrough",
                     url="/uploads/a.php", srcip="8.8.4.4", srcintfrole="wan",
                     dstip="10.10.20.20", dstintfrole="dmz") for i in range(6)]
    noise = [fg_line(at(i), action="accept", srcip=f"10.10.10.{i + 1}", srcintfrole="lan",
                     dstip=f"20.0.0.{i + 1}", dstintfrole="wan", sentbyte=500) for i in range(30)]
    return scan + sqli + shell + noise + list(extra)


@pytest.fixture
def run(tmp_path):
    def _go(extra=()):
        log = write_log(tmp_path / "f.log", _lines(extra))
        gt = tmp_path / "gt.yaml"
        gt.write_text(GT)
        run_dir = tmp_path / "run"
        meta = run_killchain(log, run_dir, RULES)
        return run_dir, gt, meta
    return _go


def test_pipeline_writes_outputs(run):
    run_dir, _, meta = run()
    for name in ("incidents.json", "detection_events.parquet", "run_meta.json"):
        assert (run_dir / name).exists()
    incs = json.loads((run_dir / "incidents.json").read_text())
    assert len(incs) == 2 == meta["incident_count"]
    assert {"timeline", "path", "reach", "report"} <= set(incs[0])
    assert incs[0]["risk_score"] >= incs[1]["risk_score"]
    assert incs[0]["first_seen"].endswith("+05:30")
    assert meta["ingest"]["lines_parsed"] == 168


def test_load_run_by_id(run):
    run_dir, _, _ = run()
    by_id = load_run(run_dir)
    assert sorted(by_id) == [1, 2]
    assert by_id[1]["incident_id"] == 1


def test_evaluate_perfect_fixture(run):
    run_dir, gt, _ = run()
    m = evaluate(run_dir, gt)
    assert m.detection_rate == 1.0 and m.label_accuracy == 1.0
    assert (m.paths_rebuilt, m.paths_total) == (2, 2)
    assert m.false_alarm_rate == 0.0
    assert m.p95_open_ms < 500


def test_evaluate_counts_false_alarm(run):
    extra = [fg_line(at(300), type="utm", subtype="virus", action="detected", virus="JS/x",
                     srcip="10.10.10.77", srcintfrole="lan", dstip="6.6.6.6", dstintfrole="wan")]
    run_dir, gt, _ = run(extra)
    m = evaluate(run_dir, gt)
    assert m.false_alarm_rate == pytest.approx(1 / 3, abs=1e-3)


def test_skip_ingest_reuses_parts(run, tmp_path):
    run_dir, _, first = run()
    again = run_killchain(tmp_path / "missing.log", run_dir, RULES, skip_ingest=True)
    assert again["incident_count"] == 2
    assert again["ingest"] == first["ingest"]


def test_bench_report_renders_every_prd_target(run):
    from killchain.cli import render_benchmark
    from killchain.pipeline import load_meta

    run_dir, gt, _ = run()
    md = render_benchmark(evaluate(run_dir, gt), load_meta(run_dir))
    for name in ("Detection", "Correct labels", "Attack path", "False alarms", "Processing time",
                 "Peak memory", "Investigation speed"):
        assert name in md
    assert "Below target" not in md


GT_SAME_ATTACKER = """
scenarios:
  - id: S1
    name: scan
    steps:
      - {id: S1-1, techniques: [T1595], where: "srcip='8.8.4.4' AND type='traffic'", expected_count: 120}
  - id: S2
    name: sqli then webshell
    steps:
      - {id: S2-1, techniques: [T1190], where: "srcip='8.8.4.4' AND subtype='ips'", expected_count: 12}
      - {id: S2-2, techniques: [T1505.003], where: "srcip='8.8.4.4' AND subtype='webfilter'", expected_count: 6}
"""


def test_evaluate_penalises_merging_two_scenarios(tmp_path):
    lines = [ln.replace("9.9.9.9", "8.8.4.4") for ln in _lines()]
    run_dir = tmp_path / "run"
    run_killchain(write_log(tmp_path / "f.log", lines), run_dir, RULES)
    gt = tmp_path / "gt.yaml"
    gt.write_text(GT_SAME_ATTACKER)
    m = evaluate(run_dir, gt)
    assert m.incidents == 1 and m.merged_incidents == 1
    assert m.paths_rebuilt == 0
    assert (m.paths_multistep_rebuilt, m.paths_multistep_total) == (0, 1)


def test_evaluate_reports_purity(run):
    run_dir, gt, _ = run()
    m = evaluate(run_dir, gt)
    assert m.incident_purity == 1.0 and m.merged_incidents == 0
