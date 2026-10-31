from tests.test_kc_correlate import det
from killchain.correlate import correlate
from killchain.pathgraph import build_path, build_timeline, format_ts
from killchain.scoring import rank, score_incident


def _scan():
    (inc,) = correlate([det("S:1", "T1595", 0, n=1024, outcome="blocked",
                            src_ip="9.9.9.9", dst_ip="10.10.20.5")])
    inc.detections[0].severity = "medium"
    return inc


def _admin_chain():
    ds = [det("P:1", "T1136.001", 0, src_ip="3.3.3.3", user="ops1", account="svc_x"),
          det("L:1", "T1078", 0.1, src_ip="3.3.3.3", user="svc_x", dst_ip="10.10.99.1"),
          det("D:1", "T1070", 0.2, src_ip="3.3.3.3", user="ops1", account="svc_x")]
    for d in ds:
        d.severity = "critical"
    (inc,) = correlate(ds)
    return inc


def test_score_progression_beats_volume():
    s_scan, sev_scan = score_incident(_scan())
    s_admin, sev_admin = score_incident(_admin_chain())
    assert s_scan == 20.0 and sev_scan == "low"
    assert s_admin == 86.2 and sev_admin == "critical"


def test_rank_sorted_desc():
    ranked = rank([_scan(), _admin_chain()])
    assert [i.risk_score for i in ranked] == [86.2, 20.0]
    assert ranked[0].severity == "critical"


def test_timeline_sorted():
    tl = build_timeline(_admin_chain())
    assert [s.technique_id for s in tl] == ["T1136.001", "T1078", "T1070"]
    assert tl[0].stage == "Installation" and tl[0].event_count == 1


def test_path_admin_chain_edges():
    g = build_path(_admin_chain())
    ids = {n["id"] for n in g.nodes}
    assert {"external_ip:3.3.3.3", "user:svc_x", "user:ops1", "firewall:10.10.99.1"} <= ids
    techs = [e["technique_id"] for e in g.edges]
    assert set(techs) == {"T1136.001", "T1078", "T1070"}
    assert [e["ts"] for e in g.edges] == sorted(e["ts"] for e in g.edges)
    assert all(e["source"] in ids and e["target"] in ids for e in g.edges)


def test_path_network_detection_links_hosts():
    (inc,) = correlate([det("W:1", "T1190", 0, src_ip="1.1.1.1", dst_ip="10.10.20.20")])
    g = build_path(inc)
    assert g.edges == [{"source": "external_ip:1.1.1.1", "target": "host:10.10.20.20",
                        "technique_id": "T1190", "ts": g.edges[0]["ts"],
                        "label": "T1190 Exploit Public-Facing Application"}]
    host = next(n for n in g.nodes if n["id"] == "host:10.10.20.20")
    assert host["segment"] == "10.10.20.0/24" and host["kind"] == "host"


def test_format_ts_is_device_local():
    inc = _scan()
    assert format_ts(inc.first_seen) == "2026-10-28T10:00:00+05:30"
