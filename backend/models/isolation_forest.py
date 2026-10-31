"""
models/isolation_forest.py
Real IsolationForest-based anomaly scoring.
Replaces the random.uniform stub with sklearn.

Pipeline:
  1. Build feature matrix from all users + their events (via feature_engineering)
  2. Fit IsolationForest on the matrix
  3. Normalise raw decision_function scores → 0–100 risk_score
  4. Blend IF score with deterministic rule flags (60/40 weight)
  5. Attach event aggregates and flag codes back to each profile
"""
from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from config import get_settings
from preprocessing.feature_engineering import (
    FEATURE_NAMES,
    build_feature_matrix,
)

# ─── Rule-based flag weights ──────────────────────────────────────────────────
# Each rule contributes points to the rule_score (0–100 scale).
# Weights sum to ~100 so rule_score alone can hit max.
RULE_WEIGHTS: dict[str, float] = {
    "STALE_PRIVILEGED_ACCOUNT": 35.0,  # inactive admin
    "VERY_STALE_ACCOUNT": 25.0,        # >90d inactive any user
    "INACTIVE_ADMIN": 20.0,            # is_active=False + admin
    "AFTER_HOURS_ADMIN_OP": 18.0,      # admin_op at night
    "BULK_EXPORT": 15.0,               # ≥3 export_data events
    "HIGH_BLAST_ACCESS": 12.0,         # access to PROD-DB / SIEM etc.
    "CROSS_DEPT_ACCESS": 10.0,         # >20% events outside dept
    "HIGH_FAIL_RATE": 8.0,             # fail_ratio > 30%
    "EXCESSIVE_SYSTEMS": 8.0,          # >7 distinct systems
}


def _compute_rule_flags(
    profile: dict[str, Any], event_agg: dict[str, Any]
) -> tuple[list[str], float]:
    """Evaluate deterministic rules and return (flag_list, rule_score 0–100)."""
    priv = str(profile.get("privilege_level", "user")).strip().lower()
    days_inactive = int(profile.get("days_inactive", 0) or 0)
    is_active = bool(profile.get("is_active", True))
    systems: list[str] = profile.get("systems_access", []) or []
    is_new_hire = bool(profile.get("is_new_hire", False))

    after_hours_ratio = float(event_agg.get("after_hours_ratio", 0.0))
    export_count = int(event_agg.get("export_count", 0))
    fail_ratio = float(event_agg.get("fail_ratio", 0.0))
    admin_op_count = int(event_agg.get("admin_op_count", 0))
    cross_dept = float(event_agg.get("cross_dept_access_ratio", 0.0))
    high_blast = float(event_agg.get("unique_systems_per_day_max", 0))
    from config import get_settings

    cfg = get_settings()
    stale_threshold = cfg.STALE_DAYS_THRESHOLD
    very_stale = cfg.VERY_STALE_DAYS_THRESHOLD

    flags: list[str] = []
    raw_score = 0.0

    # New hires get a partial amnesty — don't flag cross-dept / after-hours
    amnesty = is_new_hire

    if priv == "admin" and days_inactive > stale_threshold and not amnesty:
        flags.append("STALE_PRIVILEGED_ACCOUNT")
        raw_score += RULE_WEIGHTS["STALE_PRIVILEGED_ACCOUNT"]

    if days_inactive > very_stale and not amnesty:
        flags.append("VERY_STALE_ACCOUNT")
        raw_score += RULE_WEIGHTS["VERY_STALE_ACCOUNT"]

    if priv == "admin" and not is_active:
        flags.append("INACTIVE_ADMIN")
        raw_score += RULE_WEIGHTS["INACTIVE_ADMIN"]

    if priv in {"admin", "power-user"} and after_hours_ratio > 0.3 and admin_op_count > 0 and not amnesty:
        flags.append("AFTER_HOURS_ADMIN_OP")
        raw_score += RULE_WEIGHTS["AFTER_HOURS_ADMIN_OP"]

    if export_count >= 3:
        flags.append("BULK_EXPORT")
        raw_score += RULE_WEIGHTS["BULK_EXPORT"]

    if len(systems) > 7:
        flags.append("EXCESSIVE_SYSTEMS")
        raw_score += RULE_WEIGHTS["EXCESSIVE_SYSTEMS"]

    if cross_dept > 0.2 and not amnesty:
        flags.append("CROSS_DEPT_ACCESS")
        raw_score += RULE_WEIGHTS["CROSS_DEPT_ACCESS"]

    if fail_ratio > 0.30:
        flags.append("HIGH_FAIL_RATE")
        raw_score += RULE_WEIGHTS["HIGH_FAIL_RATE"]

    # Cap rule score at 100
    rule_score = min(raw_score, 100.0)
    return flags, rule_score


def score_users(
    profiles: list[dict[str, Any]],
    all_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Replaces the random stub.
    Mutates each profile in-place with:
      risk_score, anomaly_score_raw, flags, event_count,
      after_hours_ratio, high_sensitivity_ratio, fail_ratio,
      export_count, admin_op_count, flagged_events
    """
    feature_matrix, event_agg_list, _ = build_feature_matrix(profiles, all_events)

    n_users = len(profiles)
    if n_users < 2:
        # Too few samples to fit IsolationForest meaningfully
        for i, profile in enumerate(profiles):
            agg = event_agg_list[i]
            flags, rule_score = _compute_rule_flags(profile, agg)
            _stamp_profile(profile, agg, flags, rule_score, if_score=50.0)
        return profiles

    cfg = get_settings()
    iso = IsolationForest(
        n_estimators=200,
        contamination=cfg.ISOLATION_FOREST_CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(feature_matrix)

    # decision_function returns negative = anomaly, positive = normal
    # We invert and normalise so higher value = more anomalous
    raw_scores = iso.decision_function(feature_matrix)  # shape (n,)
    inverted = -raw_scores  # now higher = more anomalous

    scaler = MinMaxScaler(feature_range=(0.0, 100.0))
    if_scores_normalized: np.ndarray = scaler.fit_transform(
        inverted.reshape(-1, 1)
    ).flatten()

    for i, profile in enumerate(profiles):
        agg = event_agg_list[i]
        flags, rule_score = _compute_rule_flags(profile, agg)
        if_score = float(if_scores_normalized[i])
        profile["anomaly_score_raw"] = round(float(raw_scores[i]), 4)
        _stamp_profile(profile, agg, flags, rule_score, if_score)

    return profiles


def _stamp_profile(
    profile: dict[str, Any],
    agg: dict[str, Any],
    flags: list[str],
    rule_score: float,
    if_score: float,
) -> None:
    """Write all computed signals into the profile dict."""
    # Blended score: 60% IF + 40% rule-based
    blended = 0.60 * if_score + 0.40 * rule_score
    profile["risk_score"] = round(min(blended, 100.0), 2)
    profile["flags"] = flags

    # Event metrics
    profile["event_count"] = agg.get("event_count", 0)
    profile["after_hours_ratio"] = round(agg.get("after_hours_ratio", 0.0), 4)
    profile["high_sensitivity_ratio"] = round(agg.get("high_sensitivity_ratio", 0.0), 4)
    profile["fail_ratio"] = round(agg.get("fail_ratio", 0.0), 4)
    profile["export_count"] = agg.get("export_count", 0)
    profile["admin_op_count"] = agg.get("admin_op_count", 0)
    profile["login_fail_count"] = agg.get("login_fail_count", 0)
    profile["flagged_events"] = agg.get("flagged_events", [])
