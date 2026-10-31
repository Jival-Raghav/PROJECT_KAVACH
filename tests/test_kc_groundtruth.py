from tests.kc_fixture import REPO, fg_line, ingest_lines
from killchain.groundtruth import load_ground_truth, resolve_steps
from killchain.store import open_events


def test_resolve_steps_on_fixture(tmp_path):
    run = ingest_lines(tmp_path, [fg_line(type="utm", subtype="ips", srcip="1.2.3.4"),
                                  fg_line(type="utm", subtype="ips", srcip="5.6.7.8")])
    gt = tmp_path / "gt.yaml"
    gt.write_text("scenarios:\n- id: S\n  name: s\n  steps:\n  - id: S-1\n"
                  "    techniques: [T1190]\n    where: \"srcip='1.2.3.4'\"\n    expected_count: 1\n")
    steps = resolve_steps(open_events(run), load_ground_truth(gt))
    assert steps == {"S-1": {1}}


def test_real_ground_truth_shape():
    sc = load_ground_truth(REPO / "data/ground_truth/firex_planted.yaml")
    assert len(sc) == 19 and sum(len(s.steps) for s in sc) == 23
    assert all(s.steps and all(st.techniques for st in s.steps) for s in sc)
