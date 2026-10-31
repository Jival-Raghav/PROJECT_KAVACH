from tests.kc_fixture import at, fg_line, ingest_lines
from tests.test_kc_correlate import det
from killchain.correlate import correlate
from killchain.reach import build_network_graph, next_reach
from killchain.store import open_events

ASSETS = {
    "firewall_mgmt_ip": "10.0.99.1",
    "segments": [
        {"cidr": "10.0.0.0/24", "name": "LAN", "sensitivity": "medium"},
        {"cidr": "10.0.1.0/24", "name": "Servers", "sensitivity": "high"},
        {"cidr": "10.0.99.0/24", "name": "Management", "sensitivity": "crown"},
    ],
}


def _graph(tmp_path):
    lines = [
        fg_line(at(0), action="accept", srcip="10.0.0.5", dstip="10.0.1.7", dstport=445),
        fg_line(at(1), action="accept", srcip="10.0.0.6", dstip="8.8.8.8", dstport=443),
        fg_line(at(2), action="accept", srcip="10.0.99.20", dstip="8.8.8.8", dstport=443),
        fg_line(at(3), action="deny", srcip="10.0.0.5", dstip="10.0.99.20", dstport=22),
    ]
    return build_network_graph(open_events(ingest_lines(tmp_path, lines)), ASSETS)


def test_graph_has_hosts_and_observed_edges(tmp_path):
    g = _graph(tmp_path)
    assert {"system:10.0.0.5", "system:10.0.1.7", "system:10.0.0.6", "system:firewall"} <= set(g)
    assert g.nodes["system:10.0.1.7"]["sensitivity"] == "high"
    assert g.edges["system:10.0.0.5", "system:10.0.1.7"]["basis"] == "observed"
    assert not g.has_edge("system:10.0.0.5", "system:10.0.99.20")  # denied traffic is no path


def test_host_foothold_uses_observed_edges(tmp_path):
    g = _graph(tmp_path)
    (inc,) = correlate([det("B:1", "T1071.001", 0, src_ip="10.0.0.5", dst_ip="7.7.7.7")])
    r = next_reach(inc, g, ASSETS)
    assert r.footholds == ["10.0.0.5"]
    observed = [t for t in r.targets if t.basis == "observed"]
    assert [(t.label, t.hops, t.sensitivity) for t in observed] == [("10.0.1.7", 1, "high")]
    assert any(t.label == "10.0.0.6" and t.basis == "same_segment" for t in r.targets)
    assert r.targets[0].label == "10.0.1.7"  # highest sensitivity first


def test_admin_incident_reaches_all_segments(tmp_path):
    g = _graph(tmp_path)
    (inc,) = correlate([det("P:1", "T1136.001", 0, src_ip="3.3.3.3", user="ops", account="x")])
    r = next_reach(inc, g, ASSETS)
    assert "firewall" in r.footholds
    assert {t.segment for t in r.targets if t.basis == "admin_control"} == {
        "LAN", "Servers", "Management"}
    assert "firewall" in r.summary.lower() and "Management" in r.summary


def test_blocked_only_incident_has_no_footholds(tmp_path):
    g = _graph(tmp_path)
    (inc,) = correlate([det("S:1", "T1595", 0, outcome="blocked", src_ip="9.9.9.9",
                            dst_ip="10.0.1.7")])
    r = next_reach(inc, g, ASSETS)
    assert r.footholds == [] and r.targets == []
    assert "no foothold" in r.summary.lower()
