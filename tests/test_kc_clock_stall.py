"""A stopped log clock is detected at ingest and kept away from detection logic."""
import json

from killchain.cli import render_benchmark
from killchain.evaluate import Metrics
from killchain.ingest import ingest_log, peak_rss_mb
from killchain.rules import load_rules, run_rules
from killchain.store import STALL_MIN_LINES, open_events
from tests.kc_fixture import REPO, at, fg_line, ingest_lines, write_log


def _scan_at(when, count=120):
    return [fg_line(when, action="deny", srcip="9.9.9.9", srcintfrole="wan", dstip="10.10.20.5",
                    dstintfrole="dmz", dstport=p) for p in range(1, count + 1)]


def _frozen(count=STALL_MIN_LINES):
    return [fg_line(at(500), action="accept", srcip="10.10.10.1", dstip="20.0.0.1")] * count


def test_stalled_lines_are_recorded_and_hidden_from_events(tmp_path):
    normal = [fg_line(at(i), action="accept", srcip="10.10.10.2", dstip="20.0.0.2")
              for i in range(5)]
    run = ingest_lines(tmp_path, normal + _frozen())
    stalls = json.loads((run / "clock_stalls.json").read_text())
    assert [(s["lines"], s["first_line"], s["last_line"]) for s in stalls] == [
        (STALL_MIN_LINES, 6, STALL_MIN_LINES + 5)]
    con = open_events(run)
    assert con.execute("select count(*) from events").fetchone()[0] == 5
    assert con.execute("select count(*) from events_all").fetchone()[0] == STALL_MIN_LINES + 5


def test_lines_below_the_threshold_are_not_a_stall(tmp_path):
    run = ingest_lines(tmp_path, _frozen(STALL_MIN_LINES - 1))
    assert json.loads((run / "clock_stalls.json").read_text()) == []
    assert open_events(run).execute("select count(*) from events").fetchone()[0] == STALL_MIN_LINES - 1


def test_ingest_reports_stalled_line_count(tmp_path):
    stats = ingest_log(write_log(tmp_path / "x.log", _frozen()), tmp_path / "run")
    assert stats.lines_parsed == stats.lines_stalled == STALL_MIN_LINES


def test_attack_pattern_inside_a_stall_does_not_fire_rules(tmp_path):
    lines = _scan_at(at(500)) + _frozen()
    con = open_events(ingest_lines(tmp_path, lines))
    assert run_rules(con, load_rules(REPO / "config/detection_rules")) == []


def test_real_attack_before_a_stall_still_fires(tmp_path):
    lines = _scan_at(at(1)) + _frozen()
    con = open_events(ingest_lines(tmp_path, lines))
    ids = {d.rule_id for d in run_rules(con, load_rules(REPO / "config/detection_rules"))}
    assert "KC-RECON-001" in ids


def test_peak_memory_is_measured():
    assert peak_rss_mb() > 0


def test_unmeasured_memory_is_not_rated_as_passing():
    m = Metrics(detection_rate=1, label_accuracy=1, label_accuracy_lenient=1, paths_rebuilt=1,
                paths_total=1, paths_multistep_rebuilt=0, paths_multistep_total=0,
                merged_incidents=0, incident_purity=1, false_alarm_rate=0, incidents=1,
                false_alarms=0, steps_total=1, steps_found=1, processing_seconds=1,
                peak_memory_mb=0, cold_open_ms=1, p95_open_ms=1, per_step=[], per_scenario=[])
    row = next(ln for ln in render_benchmark(m, {}).splitlines() if ln.startswith("| Peak memory"))
    assert "not measured" in row and "Great" not in row
