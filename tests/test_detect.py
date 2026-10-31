"""tests/test_detect.py
Comprehensive unit tests for Phase 3: Detection Core Generalization.

Tests:
1. Feature extraction engine with known fixtures (after hours, weekend, burst, travel, failed login).
2. Graceful degradation: features auto-skip with diagnostic reasons when source fields are absent.
3. Custom Unified Schema features dynamically change the model input matrix dimension.
4. Peer grouping: hierarchical (dept -> role) and clustering fallback (entitlement Jaccard).
5. SoD conflict engine: entitlement conflicts and action conflicts.
6. Self-calibrating Isolation Forest contamination estimation.
7. Score fusion: 60% ML + 40% heuristic weighting and hard-rule escalation.
8. Peer z-score outlier detection (z > 2.0).
"""
from __future__ import annotations


import numpy as np
import pytest
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEntitlement,
    CanonicalEvent,
    CanonicalIdentity,
)
from detect.features import extract_canonical_features
from detect.heuristics import SoDRule, evaluate_heuristics
from detect.models import run_detection
from detect.peers import build_peer_groups, compute_peer_medians, evaluate_peer_zscores
from detect.scoring import (
    estimate_knee_contamination,
    fuse_scores,
    normalize_to_100,
)


@pytest.fixture
def sample_bundle() -> CanonicalBundle:
    """Build a rich canonical test fixture."""
    identities = [
        CanonicalIdentity(
            identity_id="U001",
            full_name="Alice Smith",
            email="alice@acme.com",
            department="Engineering",
            job_title="DevOps Engineer",
            employment_status="active",
        ),
        CanonicalIdentity(
            identity_id="U002",
            full_name="Bob Jones",
            email="bob@acme.com",
            department="Engineering",
            job_title="Software Engineer",
            employment_status="active",
        ),
        CanonicalIdentity(
            identity_id="U003",
            full_name="Carol White",
            email="carol@acme.com",
            department="Finance",
            job_title="Financial Controller",
            employment_status="active",
        ),
    ]

    accounts = [
        CanonicalAccount(
            account_id="ACC_U001",
            system="AWS",
            username="alice",
            privilege_level="admin",
            last_login="2026-03-20T10:00:00Z",
            extra={"identity_id": "U001"},
        ),
        CanonicalAccount(
            account_id="ACC_U002",
            system="GitHub",
            username="bob",
            privilege_level="user",
            last_login="2026-03-25T11:00:00Z",
            extra={"identity_id": "U002"},
        ),
        CanonicalAccount(
            account_id="ACC_U003",
            system="SAP",
            username="carol",
            privilege_level="power-user",
            last_login="2026-01-10T09:00:00Z",  # Stale (>60 days)
            extra={"identity_id": "U003"},
        ),
    ]

    entitlements = [
        CanonicalEntitlement(account_id="ACC_U001", system="AWS", entitlement="AdministratorAccess", privilege_weight=10.0),
        CanonicalEntitlement(account_id="ACC_U001", system="AWS", entitlement="cloudtrail_delete", privilege_weight=8.0),
        CanonicalEntitlement(account_id="ACC_U001", system="AWS", entitlement="iam_user_create", privilege_weight=8.0),
        CanonicalEntitlement(account_id="ACC_U002", system="GitHub", entitlement="repo:write", privilege_weight=2.0),
        CanonicalEntitlement(account_id="ACC_U003", system="SAP", entitlement="vendor_create", privilege_weight=5.0),
        CanonicalEntitlement(account_id="ACC_U003", system="SAP", entitlement="payment_approve", privilege_weight=5.0),
    ]

    events = [
        # Alice: Night activity, impossible travel (US to SG in 10 minutes)
        CanonicalEvent(
            event_id="E001",
            timestamp="2026-03-25T23:15:00Z",  # Night
            user_key="U001",
            action="admin_operation",
            resource="PROD_DB",
            system="AWS",
            resource_sensitivity="crown",
            source_ip="us",
            success=True,
        ),
        CanonicalEvent(
            event_id="E002",
            timestamp="2026-03-25T23:25:00Z",  # 10 mins later from Singapore
            user_key="U001",
            action="export_data",
            resource="PROD_DB",
            system="AWS",
            resource_sensitivity="crown",
            source_ip="sg",
            success=True,
        ),
        # Bob: Normal business hours events
        CanonicalEvent(
            event_id="E003",
            timestamp="2026-03-25T14:00:00Z",  # 14:00 business hours
            user_key="U002",
            action="git_push",
            resource="repo_1",
            system="GitHub",
            resource_sensitivity="low",
            source_ip="us",
            success=True,
        ),
        CanonicalEvent(
            event_id="E004",
            timestamp="2026-03-25T14:30:00Z",
            user_key="U002",
            action="git_push",
            resource="repo_1",
            system="GitHub",
            resource_sensitivity="low",
            source_ip="us",
            success=True,
        ),
        # Carol: Failure events
        CanonicalEvent(
            event_id="E005",
            timestamp="2026-03-25T10:00:00Z",
            user_key="U003",
            action="login",
            resource="SAP",
            system="SAP",
            resource_sensitivity="high",
            source_ip="us",
            success=False,
        ),
        CanonicalEvent(
            event_id="E006",
            timestamp="2026-03-25T10:05:00Z",
            user_key="U003",
            action="login",
            resource="SAP",
            system="SAP",
            resource_sensitivity="high",
            source_ip="us",
            success=False,
        ),
    ]

    return CanonicalBundle(
        run_id="test_run",
        identities=identities,
        accounts=accounts,
        entitlements=entitlements,
        events=events,
        systems=[],
    )


def test_feature_extraction_all_fixtures(sample_bundle: CanonicalBundle):
    """Test feature extraction engine with rich canonical events and accounts."""
    peer_map = build_peer_groups(sample_bundle)
    peer_medians = compute_peer_medians(sample_bundle, peer_map)

    res = extract_canonical_features(sample_bundle, peer_medians=peer_medians)

    assert len(res.user_ids) == 3
    assert res.matrix.shape[0] == 3
    assert res.matrix.shape[1] >= 10
    assert "after_hours_ratio" in res.active_features
    assert "impossible_travel_flag" in res.active_features
    assert "sensitivity_ratio" in res.active_features

    # Alice (U001) has impossible travel (US -> SG in 10 minutes)
    alice_idx = res.user_ids.index("U001")
    col_idx = res.active_features.index("impossible_travel_flag")
    assert res.matrix[alice_idx, col_idx] == 1.0

    # Alice has night crown jewel export -> high sensitivity ratio = 1.0
    sens_idx = res.active_features.index("sensitivity_ratio")
    assert res.matrix[alice_idx, sens_idx] == 1.0

    # Carol (U003) has 100% failed logins
    carol_idx = res.user_ids.index("U003")
    fail_idx = res.active_features.index("failed_login_ratio")
    assert res.matrix[carol_idx, fail_idx] == 1.0


def test_feature_auto_skipping():
    """Verify that absent columns/sources cause features to auto-skip gracefully with reasons."""
    # Bundle without timestamps and without entitlements
    sparse_bundle = CanonicalBundle(
        run_id="sparse",
        identities=[CanonicalIdentity(identity_id="U1", full_name="User 1")],
        accounts=[CanonicalAccount(account_id="A1", system="SYS1", username="u1")],
        entitlements=[],  # No entitlements
        events=[
            CanonicalEvent(
                event_id="E1",
                timestamp="",  # Empty timestamp
                user_key="U1",
                action="read",
                resource="doc",
            )
        ],
        systems=[],
    )

    res = extract_canonical_features(sparse_bundle)

    # Time-based and entitlement-based features must be gracefully skipped
    assert "after_hours_ratio" in res.skipped_features
    assert "weekend_ratio" in res.skipped_features
    assert "unused_entitlement_ratio" in res.skipped_features
    assert "entitlement_vs_peer_median" in res.skipped_features

    # Diagnostic reasons must be provided
    assert len(res.skipped_reasons["after_hours_ratio"]) > 0
    assert len(res.skipped_reasons["unused_entitlement_ratio"]) > 0


def test_custom_feature_matrix_injection(sample_bundle: CanonicalBundle):
    """Test that custom features defined in Unified Schema dynamically alter matrix dimension."""
    # Attach a custom attribute to identities
    for ident in sample_bundle.identities:
        ident.extra["custom_threat_score"] = 75.0

    std_res = extract_canonical_features(sample_bundle)
    custom_res = extract_canonical_features(
        sample_bundle,
        custom_feature_defs=[{"name": "custom_threat_score", "field": "custom_threat_score"}],
    )

    assert custom_res.matrix.shape[1] == std_res.matrix.shape[1] + 1
    assert "custom_custom_threat_score" in custom_res.active_features


def test_peer_grouping_hierarchical_and_fallback(sample_bundle: CanonicalBundle):
    """Test peer group segmentation and fallback to clustering."""
    # 1. Hierarchical: with min_cohort_size=1 preserves specific role
    peer_map_role = build_peer_groups(sample_bundle, min_cohort_size=1)
    assert peer_map_role["U001"] == "engineering::devops engineer"
    assert peer_map_role["U002"] == "engineering::software engineer"
    assert peer_map_role["U003"] == "finance::financial controller"

    # With default min_cohort_size=3, safely rolls up to department
    peer_map_dept = build_peer_groups(sample_bundle, min_cohort_size=3)
    assert peer_map_dept["U001"] == "engineering"
    assert peer_map_dept["U003"] == "finance"

    # 2. Fallback when department is missing: falls back to entitlement Jaccard clustering
    no_dept_bundle = CanonicalBundle(
        run_id="no_dept",
        identities=[],
        accounts=sample_bundle.accounts,
        entitlements=sample_bundle.entitlements,
        events=sample_bundle.events,
        systems=[],
    )
    fallback_map = build_peer_groups(no_dept_bundle)
    assert len(fallback_map) > 0
    assert any("entitlement_cluster" in g or "action_cluster" in g for g in fallback_map.values())


def test_sod_conflict_evaluation(sample_bundle: CanonicalBundle):
    """Verify Separation of Duties engine flags entitlement conflicts and action conflicts."""
    rules = [
        SoDRule(
            rule_id="TEST_SOD_001",
            name="Procurement and Payment",
            description="Conflict between creating vendor and approving payment",
            severity="critical",
            entitlement_conflicts=[["vendor_create", "payment_approve"]],
            action_conflicts=[],
        ),
        SoDRule(
            rule_id="TEST_SOD_002",
            name="Admin and Export",
            description="Conflict between admin operation and data export",
            severity="high",
            entitlement_conflicts=[],
            action_conflicts=[["admin_operation", "export_data"]],
        ),
    ]

    findings = evaluate_heuristics(sample_bundle, sod_rules=rules)

    # Carol (U003) has both vendor_create and payment_approve entitlements
    carol_findings = [f for f in findings.get("U003", []) if f["id"] == "TEST_SOD_001_ENT"]
    assert len(carol_findings) == 1
    assert carol_findings[0]["severity"] == "critical"
    assert carol_findings[0]["hard_rule"] is True

    # Alice (U001) executed both admin_operation and export_data actions
    alice_findings = [f for f in findings.get("U001", []) if f["id"] == "TEST_SOD_002_ACT"]
    assert len(alice_findings) == 1
    assert alice_findings[0]["severity"] == "high"


def test_isolation_forest_self_calibration():
    """Verify Isolation Forest knee contamination estimation and normalization."""
    # Synthetic scores with a sharp knee at 10%
    np.random.seed(42)
    normal_scores = np.random.normal(0.2, 0.05, 90)
    anom_scores = np.random.normal(-0.3, 0.05, 10)
    all_scores = np.concatenate([anom_scores, normal_scores])

    contam = estimate_knee_contamination(all_scores, min_contamination=0.05, max_contamination=0.40)
    assert 0.05 <= contam <= 0.40

    # Normalization to 100
    norm_100 = normalize_to_100(all_scores)
    assert len(norm_100) == len(all_scores)
    assert np.min(norm_100) >= 0.0
    assert np.max(norm_100) <= 100.0
    # The anomaly scores (most negative) should receive the highest 0-100 scores
    assert np.mean(norm_100[:10]) > np.mean(norm_100[10:])


def test_score_fusion_and_thresholds():
    """Verify 60% ML + 40% Heuristic score fusion and hard rule escalation."""
    user_ids = ["U_NORMAL", "U_CRITICAL_RULE", "U_ML_ANOM"]
    ml_scores = np.array([10.0, 30.0, 95.0])

    findings = {
        "U_CRITICAL_RULE": [
            {
                "id": "SOD_CRITICAL",
                "severity": "critical",
                "score_weight": 25.0,
                "hard_rule": True,
            }
        ],
        "U_NORMAL": [],
        "U_ML_ANOM": [],
    }

    profiles = fuse_scores(
        user_ids=user_ids,
        ml_scores_100=ml_scores,
        user_findings=findings,
        weight_ml=0.60,
        weight_heuristics=0.40,
    )

    prof_map = {p["user_id"]: p for p in profiles}

    # Normal user has low risk
    assert prof_map["U_NORMAL"]["risk_score"] < 20.0
    assert prof_map["U_NORMAL"]["severity"] == "INFORMATIONAL"

    # Critical hard rule user is escalated to at least 85.0
    assert prof_map["U_CRITICAL_RULE"]["risk_score"] >= 85.0
    assert prof_map["U_CRITICAL_RULE"]["severity"] == "CRITICAL"

    # Pure ML anomaly user
    assert prof_map["U_ML_ANOM"]["risk_score"] >= 50.0


def test_peer_zscore_detection():
    """Verify peer z-score calculation flags individuals with z > 2.0."""
    user_scores = {
        "U1": 20.0,
        "U2": 22.0,
        "U3": 21.0,
        "U4": 20.5,
        "U5": 21.5,
        "U_OUTLIER": 85.0,
    }
    peer_map = {uid: "Engineering" for uid in user_scores}

    peer_results = evaluate_peer_zscores(user_scores, peer_map, z_threshold=2.0)

    assert peer_results["U_OUTLIER"]["is_peer_outlier"] is True
    assert peer_results["U_OUTLIER"]["z_score"] > 2.0
    assert peer_results["U1"]["is_peer_outlier"] is False


def test_end_to_end_detection_run(sample_bundle: CanonicalBundle):
    """Verify run_detection produces a complete DetectionResult with metrics and peer context."""
    res = run_detection(sample_bundle)

    assert res.run_id == "test_run"
    assert len(res.user_profiles) == 3
    assert res.contamination >= 0.05
    assert len(res.feature_result.active_features) > 0

    # Ensure profiles have all required presentation keys
    for p in res.user_profiles:
        assert "user_id" in p
        assert "risk_score" in p
        assert "ml_score" in p
        assert "heuristic_score" in p
        assert "severity" in p
        assert "peer_group" in p
        assert "peer_zscore" in p
        assert "findings" in p
        assert "flags" in p
