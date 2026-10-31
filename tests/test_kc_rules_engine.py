import pytest

from tests.kc_fixture import at, fg_line, ingest_lines
from killchain.rules import compile_rule, load_rules, run_rules
from killchain.store import open_events


def _rules(tmp_path, text):
    d = tmp_path / "rules"
    d.mkdir(exist_ok=True)
    (d / "r.yaml").write_text("rules:\n" + text)
    return load_rules(d)


def _run(tmp_path, lines, rule_text):
    con = open_events(ingest_lines(tmp_path, lines))
    return con, run_rules(con, _rules(tmp_path, rule_text))


def test_match_rule_emits_one_detection_per_group(tmp_path):
    lines = [fg_line(at(i), type="utm", subtype="virus", action="detected", srcip=ip)
             for i, ip in enumerate(["10.0.0.1", "10.0.0.1", "10.0.0.2"])]
    _, dets = _run(tmp_path, lines, """
- id: R1
  title: virus not blocked
  technique: T1204.002
  severity: high
  kind: match
  where: "subtype='virus' AND action='detected'"
  group_by: [srcip]
  entities: {src_ip: srcip}
""")
    assert sorted(d.event_count for d in dets) == [1, 2]
    assert {d.technique.id for d in dets} == {"T1204.002"}
    assert sorted(d.entities["src_ip"][0] for d in dets) == ["10.0.0.1", "10.0.0.2"]


SCAN_RULE = """
- id: SCAN
  title: port scan
  technique: T1595.001
  severity: medium
  kind: threshold
  where: "type='traffic' AND action='deny'"
  group_by: [srcip]
  window_minutes: 10
  min_count: 100
  distinct: {field: dstport, min: 50}
  entities: {src_ip: srcip, dst_ip: dstip}
"""


def _scan(start_min, ports):
    return [fg_line(at(start_min + i * 0.02), type="traffic", action="deny", srcip="9.9.9.9",
                    dstip="10.10.20.5", dstport=p) for i, p in enumerate(ports)]


def test_threshold_gap_session_splits(tmp_path):
    lines = _scan(0, range(1, 121)) + _scan(180, range(1, 121))
    _, dets = _run(tmp_path, lines, SCAN_RULE)
    assert len(dets) == 2 and all(d.event_count == 120 for d in dets)
    assert all(d.outcome == "blocked" for d in dets)


def test_threshold_distinct_filter(tmp_path):
    _, dets = _run(tmp_path, _scan(0, [80] * 150), SCAN_RULE)
    assert dets == []


RARE_RULE = """
- id: GEO
  title: admin login from unusual country
  technique: T1078
  severity: high
  kind: rare_for_entity
  where: "logdesc='Admin login successful'"
  baseline_where: "subtype='vpn' AND action='ssl-login'"
  key: user
  value: srccountry
  max_share: 0.01
  entities: {user: user, src_ip: srcip}
"""


def test_rare_for_entity(tmp_path):
    lines = [fg_line(at(i), type="event", subtype="vpn", action="ssl-login", user="A",
                     srccountry="Japan") for i in range(99)]
    lines += [fg_line(at(i), type="event", subtype="vpn", action="ssl-login", user="B",
                      srccountry="India") for i in range(10)]
    lines += [
        fg_line(at(200), type="event", subtype="system", logdesc="Admin login successful",
                user="A", srccountry="Russian Federation", srcip="5.5.5.5"),
        fg_line(at(201), type="event", subtype="system", logdesc="Admin login successful",
                user="B", srccountry="India", srcip="6.6.6.6"),
        fg_line(at(202), type="event", subtype="system", logdesc="Admin login successful",
                user="C", srccountry="Brazil", srcip="7.7.7.7"),
    ]
    _, dets = _run(tmp_path, lines, RARE_RULE)
    assert sorted(d.entities["user"][0] for d in dets) == ["A", "C"]


SEQ_RULE = """
- id: BF
  title: brute force then success
  technique: T1110
  severity: critical
  kind: sequence
  where: "logdesc='Admin login failed'"
  then_where: "logdesc='Admin login successful'"
  join_on: srcip
  then_within_minutes: 60
  min_count: 50
  entities: {src_ip: srcip, user: user}
"""


def _fails(n, ip="9.9.9.9"):
    return [fg_line(at(i * 0.1), type="event", subtype="system", logdesc="Admin login failed",
                    srcip=ip, user="admin") for i in range(n)]


def test_sequence(tmp_path):
    ok = fg_line(at(8), type="event", subtype="system", logdesc="Admin login successful",
                 srcip="9.9.9.9", user="admin")
    _, dets = _run(tmp_path, _fails(60) + [ok], SEQ_RULE)
    assert len(dets) == 1 and dets[0].technique.id == "T1110" and dets[0].event_count == 61


def test_sequence_without_success(tmp_path):
    _, dets = _run(tmp_path, _fails(60), SEQ_RULE)
    assert dets == []


def test_selection_sigma_modifiers(tmp_path):
    lines = [
        fg_line(at(0), type="utm", subtype="ips", attack="HTTP.URI.SQL.Injection",
                dstintfrole="dmz", srcip="1.1.1.1"),
        fg_line(at(1), type="utm", subtype="ips", attack="SSH.Connection.Brute.Force",
                dstintfrole="dmz", srcip="2.2.2.2"),
        fg_line(at(2), type="utm", subtype="ips", attack="HTTP.URI.XSS", dstintfrole="wan",
                srcip="3.3.3.3"),
    ]
    text = """
- id: SIG
  title: sigma selection
  technique: T1190
  severity: high
  kind: match
  selection: {attack|startswith: "HTTP.", dstintfrole: dmz}
  group_by: [srcip]
  entities: {src_ip: srcip}
"""
    sql, params = compile_rule(_rules(tmp_path, text)[0])
    assert "HTTP." in params and "HTTP." not in sql
    _, dets = _run(tmp_path, lines, text)
    assert [d.entities["src_ip"] for d in dets] == [["1.1.1.1"]]


def test_detection_events_table(tmp_path):
    lines = _scan(0, range(1, 121))
    con, dets = _run(tmp_path, lines, SCAN_RULE)
    total = con.execute("select count(*) from detection_events").fetchone()[0]
    assert total == sum(d.event_count for d in dets) == 120


def test_unknown_technique_rejected(tmp_path):
    with pytest.raises(ValueError):
        _rules(tmp_path, """
- id: X
  title: x
  technique: T9999
  severity: low
  kind: match
""")


def test_detection_ids_are_deterministic(tmp_path):
    lines = _scan(0, range(1, 121))
    _, a = _run(tmp_path, lines, SCAN_RULE)
    _, b = _run(tmp_path, lines, SCAN_RULE)
    assert [d.detection_id for d in a] == [d.detection_id for d in b]
