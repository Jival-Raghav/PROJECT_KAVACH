from backend.killchain.changes import append_change, diff_cycle, read_changes


def _inc(iid, title, dets):
    return {
        "incident_id": iid,
        "title": title,
        "detections": [
            {"detection_id": d, "technique": {"id": t, "name": n}} for d, t, n in dets
        ],
    }


def _renum(new=(), merged=None, withdrawn=()):
    return {"new": list(new), "merged": merged or {}, "withdrawn": list(withdrawn)}


def _diff(prev, cur, renum):
    return diff_cycle(prev, cur, renum, cycle=2, generation=5, pct=40.0)


def test_new_incident_headline():
    cur = {3: _inc(3, "Brute force to admin", [("d1", "T1110", "Brute Force")])}
    e = _diff({}, cur, _renum(new=[3]))
    assert e["new"] == [3]
    assert e["headlines"] == ["#3 new: Brute force to admin"]
    assert (e["generation"], e["cycle"], e["pct"]) == (5, 2, 40.0)
    assert e["at"].endswith("+00:00")


def test_grew_lists_only_new_steps():
    prev = {1: _inc(1, "x", [("d1", "T1110", "Brute Force")])}
    cur = {
        1: _inc(
            1,
            "x",
            [
                ("d1", "T1110", "Brute Force"),
                ("d2", "T1078", "Valid Accounts"),
                ("d3", "T1021", "Remote Services"),
            ],
        )
    }
    e = _diff(prev, cur, _renum())
    assert e["grew"] == [
        {
            "id": 1,
            "steps": [
                {"technique_id": "T1078", "technique_name": "Valid Accounts"},
                {"technique_id": "T1021", "technique_name": "Remote Services"},
            ],
        }
    ]
    assert e["headlines"] == [
        "#1 gained step T1078 Valid Accounts",
        "#1 gained step T1021 Remote Services",
    ]


def test_merged_and_withdrawn_headlines():
    e = _diff({}, {}, _renum(merged={"4": "2"}, withdrawn=[7]))
    assert e["merged"] == [{"from": 4, "into": 2}]
    assert e["withdrawn"] == [7]
    assert e["headlines"] == ["#4 merged into #2", "#7 withdrawn"]


def test_read_changes_filters_by_generation(tmp_path):
    for g in (1, 2, 3):
        append_change(tmp_path, {"generation": g})
    assert [c["generation"] for c in read_changes(tmp_path, 1)] == [2, 3]
    assert len(read_changes(tmp_path)) == 3


def test_read_changes_missing_file_is_empty(tmp_path):
    assert read_changes(tmp_path) == []
