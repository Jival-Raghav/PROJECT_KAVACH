"""Anomaly scores: leads list entities outside incidents; incidents and risk never change."""
import json
from datetime import datetime

from killchain.anomaly import score_entities, split_scores
from killchain.models import Incident
from killchain.pipeline import load_anomalies, run_killchain
from killchain.store import open_events
from tests.kc_fixture import REPO, at, fg_line, ingest_lines, write_log

RULES = REPO / "config/detection_rules"


def _traffic():
    lines = []
    for host in range(1, 41):  # ordinary hosts: a few connections each
        lines += [fg_line(at(i), action="accept", srcip=f"10.10.10.{host}", dstip="20.0.0.1",
                          dstport=443, sentbyte=500) for i in range(3)]
    # One host talks to far more destinations than its peers, below any rule's threshold pattern.
    lines += [fg_line(at(i * 0.1), action="accept", srcip="10.10.10.200",
                      dstip=f"30.0.{i // 200}.{i % 200 + 1}", dstport=1000 + i, sentbyte=90000)
              for i in range(300)]
    return lines


def _incident(*ips):
    now = datetime(2026, 10, 23)
    return Incident(incident_id=1, title="t", detections=[], first_seen=now, last_seen=now,
                    entities={"src_ip": list(ips)})


def test_every_scored_entity_has_a_reason(tmp_path):
    rows = score_entities(open_events(ingest_lines(tmp_path, _traffic())), min_score=-1)
    assert rows and all(r["reasons"] for r in rows)


def test_outlier_scores_highest_and_gets_a_reason(tmp_path):
    rows = score_entities(open_events(ingest_lines(tmp_path, _traffic())))
    assert rows[0]["entity"] == "10.10.10.200"
    assert rows[0]["kind"] == "internal_host" and rows[0]["score"] > 50
    assert rows[0]["reasons"], rows[0]
    assert all("peer median" in r for r in rows[0]["reasons"])
    behaviours = ("destinations", "destination ports", "bytes sent", "events")
    assert any(r.startswith(behaviours) and "×" in r for r in rows[0]["reasons"]), rows[0]


def test_scores_are_deterministic(tmp_path):
    con = open_events(ingest_lines(tmp_path, _traffic()))
    assert score_entities(con) == score_entities(con)


def test_entity_in_an_incident_is_context_not_a_lead():
    scored = [{"entity": "a", "kind": "internal_host", "score": 90.0, "reasons": []},
              {"entity": "b", "kind": "internal_host", "score": 80.0, "reasons": []}]
    leads, context = split_scores(scored, [_incident("a")])
    assert [r["entity"] for r in leads] == ["b"]
    assert [r["entity"] for r in context[1]] == ["a"]


def test_cutoff_is_strictly_above_fifty():
    scored = [{"entity": "x", "kind": "user", "score": 50.0, "reasons": []},
              {"entity": "y", "kind": "user", "score": 50.1, "reasons": []}]
    assert [r["entity"] for r in split_scores(scored, [])[0]] == ["y"]


def test_external_ips_use_the_higher_cutoff():
    scored = [{"entity": "1.1.1.1", "kind": "external_ip", "score": 80.0, "reasons": []},
              {"entity": "2.2.2.2", "kind": "external_ip", "score": 80.1, "reasons": []},
              {"entity": "10.0.0.1", "kind": "internal_host", "score": 60.0, "reasons": []}]
    assert [r["entity"] for r in split_scores(scored, [])[0]] == ["2.2.2.2", "10.0.0.1"]


def test_anomalies_never_create_incidents(tmp_path):
    run_dir = tmp_path / "run"
    meta = run_killchain(write_log(tmp_path / "f.log", _traffic()), run_dir, RULES)
    assert meta["incident_count"] == 0
    assert json.loads((run_dir / "incidents.json").read_text()) == []
    assert "10.10.10.200" in {r["entity"] for r in load_anomalies(run_dir)}
