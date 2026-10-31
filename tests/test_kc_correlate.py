from datetime import UTC, datetime, timedelta

from killchain.correlate import correlate
from killchain.mitre import label
from killchain.models import Detection

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)


def det(did, tech, start_h, end_h=None, n=1, outcome="allowed", **entities):
    return Detection(
        detection_id=did, rule_id=did.split(":")[0], title=f"title {did}", technique=label(tech),
        severity="high", first_seen=T0 + timedelta(hours=start_h),
        last_seen=T0 + timedelta(hours=end_h if end_h is not None else start_h),
        event_count=n, entities={k: v if isinstance(v, list) else [v] for k, v in entities.items()},
        outcome=outcome)


def test_shared_victim_not_merged():
    a = det("W:1", "T1190", 0, src_ip="1.1.1.1", dst_ip="10.10.20.20")
    b = det("W:2", "T1190", 2, src_ip="2.2.2.2", dst_ip="10.10.20.20")
    assert len(correlate([a, b])) == 2


def test_same_attacker_merged_in_order():
    a = det("W:1", "T1190", 0, n=60, src_ip="1.1.1.1", dst_ip="10.10.20.20")
    b = det("S:1", "T1505.003", 0.5, n=40, src_ip="1.1.1.1", dst_ip="10.10.20.20")
    (inc,) = correlate([b, a])
    assert inc.tactics == ["initial-access", "persistence"]
    assert [d.detection_id for d in inc.detections] == ["W:1", "S:1"]
    assert inc.raw_alert_count == 100


def test_admin_chain_by_src_ip():
    ds = [det("P:1", "T1136.001", 0, src_ip="3.3.3.3", user="ops1"),
          det("L:1", "T1078", 0.1, src_ip="3.3.3.3", user="svc_x"),
          det("D:1", "T1070", 0.2, src_ip="3.3.3.3", user="ops1")]
    (inc,) = correlate(ds)
    assert len(inc.detections) == 3 and inc.raw_alert_count == 3
    assert inc.entities["user"] == ["ops1", "svc_x"]


def test_outbound_chain_linked_by_external_destination():
    ds = [det("M:1", "T1204.002", 0, src_ip="10.10.10.5", dst_ip="7.7.7.7"),
          det("B:1", "T1071.001", 1, 30, src_ip="10.10.10.5", dst_ip="7.7.7.7"),
          det("X:1", "T1041", 35, src_ip="10.10.10.5", dst_ip="7.7.7.7")]
    assert len(correlate(ds)) == 1


def test_pivot_link_requires_order():
    a = det("A:1", "T1190", 0, src_ip="1.1.1.1", dst_ip="10.0.0.5")
    b_after = det("B:1", "T1041", 1, src_ip="10.0.0.5", dst_ip="9.9.9.9")
    assert len(correlate([a, b_after])) == 1
    b_before = det("B:2", "T1041", -24, src_ip="10.0.0.5", dst_ip="9.9.9.9")
    assert len(correlate([a, b_before])) == 2


def test_pivot_gap_limit():
    a = det("A:1", "T1021.002", 0, src_ip="10.0.0.1", dst_ip=["10.0.0.5", "10.0.0.6"])
    b = det("B:1", "T1041", 26, src_ip="10.0.0.5", dst_ip="9.9.9.9")
    assert len(correlate([a, b])) == 2


def test_strong_gap_limit():
    a = det("W:1", "T1190", 0, src_ip="1.1.1.1", dst_ip="10.10.20.20")
    b = det("W:2", "T1190", 24 * 5, src_ip="1.1.1.1", dst_ip="10.10.20.20")
    assert len(correlate([a, b])) == 2


def test_incident_ids_ordered_by_time_and_title_names_attacker():
    a = det("W:1", "T1190", 5, src_ip="1.1.1.1", dst_ip="10.10.20.20")
    b = det("S:1", "T1595", 0, src_ip="2.2.2.2", dst_ip="10.10.20.21")
    incs = correlate([a, b])
    assert [i.incident_id for i in incs] == [1, 2]
    assert incs[0].title.startswith("2.2.2.2")
    assert incs[1].stages == ["Exploitation"]


def test_same_internal_actor_close_in_time_merged():
    a = det("L1:1", "T1021.002", 0, 0.4, src_ip="10.0.0.9", dst_ip=["10.0.1.1", "10.0.1.2"])
    b = det("L2:1", "T1021.001", 0.1, 0.4, src_ip="10.0.0.9", dst_ip=["10.0.1.3"])
    assert len(correlate([a, b])) == 1


def test_same_internal_actor_far_apart_not_merged():
    a = det("L1:1", "T1021.002", 0, src_ip="10.0.0.9", dst_ip=["10.0.1.1"])
    b = det("L2:1", "T1021.001", 30, src_ip="10.0.0.9", dst_ip=["10.0.1.3"])
    assert len(correlate([a, b])) == 2


def test_title_prefers_external_destination_over_internal_source():
    a = det("C:1", "T1071", 0, src_ip=["10.10.40.1", "10.10.40.2"], dst_ip="154.0.0.1")
    (inc,) = correlate([a])
    assert inc.title.startswith("154.0.0.1")
