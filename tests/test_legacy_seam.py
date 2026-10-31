"""
tests/test_legacy_seam.py — Regression test for Phase 0 adapter seam.
Verifies that loading data via the CanonicalBundle seam reproduces the legacy
pipeline outputs within tolerance (+/- 1e-6).
"""
import data_loader
import schemas
from ingest.legacy_adapter import canonical_to_legacy_dicts, load_canonical
from models import isolation_forest


def test_canonical_bundle_structure():
    bundle = load_canonical(run_id="test_run")
    assert bundle.run_id == "test_run"
    assert len(bundle.identities) == 300
    assert len(bundle.accounts) == 300
    assert len(bundle.events) == 900
    assert len(bundle.entitlements) > 0
    assert len(bundle.systems) > 0

    first_ident = bundle.identities[0]
    assert first_ident.identity_id != ""
    assert first_ident.department is not None

    first_event = bundle.events[0]
    assert first_event.event_id != ""
    assert first_event.timestamp != ""
    assert first_event.action != ""


def test_regression_scores_match():
    # 1. Run direct legacy path
    raw_users_orig = data_loader.load_users()
    raw_events_orig = data_loader.load_events()
    profiles_orig = [schemas.make_stub_profile(u) for u in raw_users_orig]
    isolation_forest.score_users(profiles_orig, raw_events_orig)

    # 2. Run via canonical adapter seam
    bundle = load_canonical(run_id="regression_test")
    raw_users_adapted, raw_events_adapted = canonical_to_legacy_dicts(bundle)
    profiles_adapted = [schemas.make_stub_profile(u) for u in raw_users_adapted]
    isolation_forest.score_users(profiles_adapted, raw_events_adapted)

    # 3. Assert equality across all 300 users
    assert len(profiles_orig) == len(profiles_adapted)

    for p_orig, p_adap in zip(profiles_orig, profiles_adapted):
        assert p_orig["user_id"] == p_adap["user_id"]
        # Raw scores match within float tolerance
        assert abs(p_orig["anomaly_score_raw"] - p_adap["anomaly_score_raw"]) < 1e-5
        # Risk scores match within 1e-4
        assert abs(p_orig["risk_score"] - p_adap["risk_score"]) < 1e-4
        # Flag list matches
        assert sorted(p_orig["flags"]) == sorted(p_adap["flags"])
