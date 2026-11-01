"""Response plans and compliance: proposals only, approval required, unsafe values never run."""
import pytest

from config import get_settings
from killchain import response
from killchain.compliance import evaluate_controls, incident_controls, load_controls
from pathlib import Path


def _det(tech, outcome="allowed", tactic="initial-access", **entities):
    return {"technique": {"id": tech, "tactic": tactic}, "outcome": outcome, "entities": entities}


def _inc(*dets, incident_id=1, risk=50):
    inc = {"incident_id": incident_id, "risk_score": risk, "detections": list(dets)}
    inc["response"] = response.build_actions(inc)
    return inc


def _ids(inc):
    return {a["action_id"] for a in inc["response"]}


def test_actions_match_what_happened():
    inc = _inc(_det("T1190", src_ip=["1.1.1.1"], dst_ip=["10.10.20.20"]),
               _det("T1505.003", tactic="persistence", src_ip=["1.1.1.1"], dst_ip=["10.10.20.20"]))
    assert _ids(inc) == {"block_ip:1.1.1.1", "inspect_host:10.10.20.20",
                         "remove_webshell:10.10.20.20"}


def test_blocked_attack_does_not_touch_the_internal_target():
    inc = _inc(_det("T1190", "blocked", src_ip=["1.1.1.1"], dst_ip=["10.10.20.20"]))
    assert _ids(inc) == {"block_ip:1.1.1.1"}


def test_blocked_c2_still_isolates_the_internal_source():
    inc = _inc(_det("T1071", "blocked", "command-and-control", src_ip=["10.10.40.5"], dst_ip=["7.7.7.7"]))
    assert _ids(inc) == {"isolate_host:10.10.40.5", "block_ip:7.7.7.7"}


def test_hosts_beyond_the_cap_are_flagged_not_dropped():
    many = [f"10.10.40.{i}" for i in range(1, 51)]
    inc = _inc(_det("T1071", "blocked", "command-and-control", src_ip=many, dst_ip=["7.7.7.7"]))
    extra = [a for a in inc["response"] if a["kind"] == "review_hosts"]
    assert len(extra) == 1 and "at least 25 more" in extra[0]["title"]


def test_small_incident_has_no_review_hosts_action():
    inc = _inc(_det("T1190", src_ip=["1.1.1.1"], dst_ip=["10.10.20.20"]))
    assert not [a for a in inc["response"] if a["kind"] == "review_hosts"]


def test_tampering_gets_restore_actions():
    inc = _inc(_det("T1562.001", "allowed", "defense-evasion", user=["x"]),
               _det("T1562.004", "allowed", "defense-evasion", user=["x"]))
    assert {"restore_logging:firewall", "restore_policy:firewall", "disable_account:x"} <= _ids(inc)


def test_approval_is_required_before_export(tmp_path):
    inc = _inc(_det("T1190", "blocked", src_ip=["1.1.1.1"]))
    assert "set subnet" not in response.export_script({1: inc}, tmp_path)
    response.transition(tmp_path, "block_ip:1.1.1.1", "approved", _ids(inc))
    script = response.export_script({1: inc}, tmp_path)
    assert "DRY RUN" in script and "set subnet 1.1.1.1/32" in script
    assert response.all_actions({1: inc}, tmp_path)[0]["status"] == "exported"
    assert "set subnet" not in response.export_script({1: inc}, tmp_path)


def test_invalid_transitions_are_refused(tmp_path):
    ids = {"block_ip:1.1.1.1"}
    with pytest.raises(ValueError):
        response.transition(tmp_path, "block_ip:1.1.1.1", "exported", ids)
    with pytest.raises(KeyError):
        response.transition(tmp_path, "block_ip:9.9.9.9", "approved", ids)
    response.transition(tmp_path, "block_ip:1.1.1.1", "rejected", ids)
    with pytest.raises(ValueError):
        response.transition(tmp_path, "block_ip:1.1.1.1", "approved", ids)


def test_every_decision_is_audited(tmp_path):
    ids = {"block_ip:1.1.1.1"}
    response.transition(tmp_path, "block_ip:1.1.1.1", "approved", ids, note="confirmed")
    entry = response.read_audit(tmp_path)[0]
    assert entry["from"] == "proposed" and entry["to"] == "approved" and entry["note"] == "confirmed"


@pytest.mark.parametrize("evil", ['x"\nexecute factoryreset\n', 'a" ; end', "a b"])
def test_malicious_account_name_never_becomes_a_command(tmp_path, evil):
    inc = _inc(_det("T1078", user=[evil]))
    action_id = f"disable_account:{evil}"
    response.transition(tmp_path, action_id, "approved", {action_id})
    script = response.export_script({1: inc}, tmp_path)
    assert "MANUAL STEP" in script and "config user local" not in script
    assert "\nexecute factoryreset" not in script


def test_malformed_ip_never_becomes_a_command(tmp_path):
    action = {"kind": "block_ip", "target": "1.1.1.1/0\nend"}
    assert response._commands(action) is None


def _controls():
    return load_controls(Path(get_settings().KILLCHAIN_CONTROLS_PATH))


def test_control_statuses():
    incidents = {1: _inc(_det("T1190", "mixed", src_ip=["1.1.1.1"])),
                 2: _inc(_det("T1204.002", "blocked"), incident_id=2)}
    rows = {r["id"]: r for r in evaluate_controls(incidents, _controls())["controls"]}
    assert rows["BOUNDARY"]["status"] == "gap" and rows["BOUNDARY"]["failed_in"] == [1]
    assert rows["MALWARE"]["status"] == "attempted" and rows["MALWARE"]["attempted_in"] == [2]
    assert rows["SEGMENTATION"]["status"] == "no_failure_seen"


def test_clean_control_is_never_called_compliant():
    result = evaluate_controls({}, _controls())
    assert result["counts"]["gap"] == 0 and "not prove" in result["notice"]
    assert {r["status"] for r in result["controls"]} == {"no_failure_seen"}


def test_incident_lists_only_controls_it_touches():
    inc = _inc(_det("T1190", "mixed", src_ip=["1.1.1.1"]))
    assert [r["id"] for r in incident_controls(inc, _controls())] == ["BOUNDARY"]


def test_every_catalogue_technique_is_known():
    from killchain.mitre import label

    for control in _controls():
        for technique in control["techniques"]:
            assert label(technique)
