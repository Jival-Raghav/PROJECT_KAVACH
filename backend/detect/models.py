"""backend/detect/models.py
Isolation Forest & Behavioral Clustering Detection Models for ISPAD v2.

Features:
- Fixed random seeds for reproducible demo metrics.
- Self-calibrating contamination parameter.
- Feature matrix scaling.
- Behavioral event clustering via KMeans (k=5).
- Full end-to-end detection pipeline integration.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np
from config import get_settings
from core.models import CanonicalBundle
from detect.features import FeatureExtractionResult, extract_canonical_features
from detect.heuristics import evaluate_heuristics, load_sod_rules
from detect.peers import build_peer_groups, compute_peer_medians, evaluate_peer_zscores
from detect.scoring import (
    estimate_knee_contamination,
    evaluate_detection_metrics,
    fuse_scores,
    normalize_to_100,
)
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class DetectionResult:

    def __init__(
        self,
        run_id: str,
        user_profiles: list[dict[str, Any]],
        feature_result: FeatureExtractionResult,
        peer_outliers: dict[str, dict[str, Any]],
        metrics: dict[str, Any],
        contamination: float,
    ):
        self.run_id = run_id
        self.user_profiles = user_profiles
        self.feature_result = feature_result
        self.peer_outliers = peer_outliers
        self.metrics = metrics
        self.contamination = contamination


def train_isolation_forest(
    X: np.ndarray,
    contamination: float | None = None,
    self_calibrate: bool = True,
    random_state: int | None = None,
) -> tuple[IsolationForest, np.ndarray, float]:
    """Train Isolation Forest with optional score-distribution knee calibration."""
    cfg = get_settings()
    seed = random_state if random_state is not None else getattr(cfg, "RANDOM_SEED", 42)

    # Standardize feature matrix
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X) if X.shape[1] > 0 else X

    if contamination is None:
        if self_calibrate:
            # Preliminary fit with default contamination to estimate distribution knee
            pre_model = IsolationForest(
                n_estimators=100,
                contamination="auto",
                random_state=seed,
            )
            pre_model.fit(X_scaled)
            pre_scores = pre_model.decision_function(X_scaled)
            final_contamination = estimate_knee_contamination(pre_scores)
        else:
            final_contamination = getattr(cfg, "ISOLATION_FOREST_CONTAMINATION", 0.35)
    else:
        final_contamination = contamination

    model = IsolationForest(
        n_estimators=200,
        contamination=final_contamination,
        random_state=seed,
    )
    model.fit(X_scaled)
    raw_decision_scores = model.decision_function(X_scaled)

    return model, raw_decision_scores, final_contamination


def cluster_behavioral_events(
    bundle: CanonicalBundle,
    k: int = 5,
    random_state: int | None = None,
) -> dict[str, Any]:
    """Cluster raw events into behavioral groups using KMeans."""
    events = bundle.events
    if not events:
        return {"clusters": [], "k": 0}

    cfg = get_settings()
    seed = random_state if random_state is not None else getattr(cfg, "RANDOM_SEED", 42)

    all_actions = sorted({e.action for e in events if e.action})
    act_to_idx = {a: i for i, a in enumerate(all_actions)}

    # Build per-event feature representation
    feature_rows = []
    for e in events:
        vec = [0.0] * len(all_actions)
        if e.action in act_to_idx:
            vec[act_to_idx[e.action]] = 1.0

        # Sensitivity weight
        sens = str(e.resource_sensitivity).lower()
        sens_val = 3.0 if sens == "crown" else (2.0 if sens == "high" else (1.0 if sens == "medium" else 0.0))
        vec.append(sens_val)

        # Success flag
        vec.append(1.0 if e.success else 0.0)
        feature_rows.append(vec)

    X = np.array(feature_rows, dtype=float)
    actual_k = min(k, len(events))
    if actual_k < 2:
        return {"clusters": [{"cluster_id": 0, "size": len(events)}], "k": 1}

    km = KMeans(n_clusters=actual_k, random_state=seed, n_init=5)
    labels = km.fit_predict(X)

    cluster_summaries = []
    for c_id in range(actual_k):
        c_events = [events[i] for i, lbl in enumerate(labels) if lbl == c_id]
        top_actions = {}
        for ev in c_events:
            top_actions[ev.action] = top_actions.get(ev.action, 0) + 1

        sorted_acts = sorted(top_actions.items(), key=lambda x: x[1], reverse=True)[:3]

        cluster_summaries.append({
            "cluster_id": c_id,
            "size": len(c_events),
            "top_actions": [{"action": a, "count": cnt} for a, cnt in sorted_acts],
        })

    return {"clusters": cluster_summaries, "k": actual_k}


def run_detection(
    bundle: CanonicalBundle,
    contamination: float | None = None,
    self_calibrate: bool | None = None,
    custom_feature_defs: list[dict[str, Any]] | None = None,
) -> DetectionResult:
    """Run complete Phase 3 Generalized Detection pipeline on a CanonicalBundle."""
    cfg = get_settings()
    do_self_calibrate = self_calibrate if self_calibrate is not None else getattr(cfg, "IF_SELF_CALIBRATE", True)

    # 1. Peer Group Segmentation & Median Baseline Calculation
    user_peer_map = build_peer_groups(bundle)
    peer_medians = compute_peer_medians(bundle, user_peer_map)

    # 2. Extract Canonical Feature Matrix (Auto-skips missing attributes)
    feat_result = extract_canonical_features(
        bundle=bundle,
        peer_medians=peer_medians,
        custom_feature_defs=custom_feature_defs,
    )

    # 3. Fit Self-Calibrating Isolation Forest
    if feat_result.matrix.shape[1] > 0 and len(feat_result.user_ids) > 0:
        _, raw_scores, final_contamination = train_isolation_forest(
            X=feat_result.matrix,
            contamination=contamination,
            self_calibrate=do_self_calibrate,
        )
        ml_scores_100 = normalize_to_100(raw_scores)
    else:
        ml_scores_100 = np.zeros(len(feat_result.user_ids))
        final_contamination = 0.15

    # 4. Evaluate Security Heuristics & SoD Rules
    sod_rules = load_sod_rules()
    user_findings = evaluate_heuristics(
        bundle=bundle,
        user_peer_map=user_peer_map,
        sod_rules=sod_rules,
    )

    # 5. Score Fusion (ML 60% + Heuristics 40%)
    fused_profiles = fuse_scores(
        user_ids=feat_result.user_ids,
        ml_scores_100=ml_scores_100,
        user_findings=user_findings,
    )

    # 6. Evaluate Peer Z-Scores & Org Anomalies (z > 2.0)
    score_map = {p["user_id"]: p["risk_score"] for p in fused_profiles}
    peer_outliers = evaluate_peer_zscores(
        user_scores=score_map,
        user_peer_map=user_peer_map,
        z_threshold=getattr(cfg, "PEER_ZSCORE_THRESHOLD", 2.0),
    )

    # Attach peer context to user profiles
    for p in fused_profiles:
        uid = p["user_id"]
        p_info = peer_outliers.get(uid, {})
        p["peer_group"] = p_info.get("peer_group", "general")
        p["peer_zscore"] = p_info.get("z_score", 0.0)
        p["is_peer_outlier"] = p_info.get("is_peer_outlier", False)

        if p.get("is_peer_outlier"):
            p["findings"].append({
                "id": "ORG_ANOMALY_PEER_OUTLIER",
                "type": "peer_outlier",
                "name": "Org Anomaly (Peer Outlier)",
                "severity": "medium",
                "description": f"Risk score is {p['peer_zscore']} standard deviations above peer baseline ({p_info.get('peer_mean', 0.0)})",
                "hard_rule": False,
                "score_weight": 10.0,
            })
            p["flags"].append("Org Anomaly (Peer Outlier)")

    # 7. Ground Truth Evaluation if labels exist
    ground_truth_labels: list[int] = []
    risk_arr: list[float] = []

    # Map labels from events if available
    labels_by_user: dict[str, int] = defaultdict(int)
    has_labels = False
    for ev in bundle.events:
        if ev.label is not None:
            has_labels = True
            if ev.label:
                labels_by_user[ev.user_key] = 1

    if has_labels:
        for p in fused_profiles:
            ground_truth_labels.append(labels_by_user.get(p["user_id"], 0))
            risk_arr.append(p["risk_score"])

        metrics = evaluate_detection_metrics(
            y_true=np.array(ground_truth_labels),
            risk_scores=np.array(risk_arr),
            threshold=50.0,
        )
    else:
        metrics = {"status": "unlabelled"}

    return DetectionResult(
        run_id=bundle.run_id or "default",
        user_profiles=fused_profiles,
        feature_result=feat_result,
        peer_outliers=peer_outliers,
        metrics=metrics,
        contamination=final_contamination,
    )
