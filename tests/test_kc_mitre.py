import pytest
import yaml

from tests.kc_fixture import REPO
from killchain.mitre import label, load_catalogue


def test_label_known():
    t = label("T1110")
    assert t.name == "Brute Force"
    assert t.tactic == "credential-access"
    assert t.stage == "Actions on Objectives"


def test_label_unknown_raises():
    with pytest.raises(KeyError):
        label("T9999")


def test_catalogue_covers_ground_truth():
    gt = yaml.safe_load((REPO / "data/ground_truth/firex_planted.yaml").read_text())
    cat = load_catalogue()
    used = {t for sc in gt["scenarios"] for st in sc["steps"] for t in st["techniques"]}
    assert used and used <= set(cat)


def test_stage_index_order():
    assert (label("T1595").stage_index < label("T1190").stage_index
            < label("T1071").stage_index < label("T1041").stage_index)


def test_tactic_slugs_used_by_correlation():
    assert label("T1190").tactic == "initial-access"
    assert label("T1505.003").tactic == "persistence"
