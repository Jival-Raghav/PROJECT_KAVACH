"""
preprocessing/feature_engineering.py
The most critical file for ML performance.

Produces a flat feature matrix where each row = one user,
and a parallel list of per-user event features used for clustering.
All values are numeric so sklearn can consume them directly.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import numpy as np


# ─── Constants ────────────────────────────────────────────────────────────────

PRIVILEGE_SCORE: dict[str, int] = {
    "user": 1,
    "power-user": 2,
    "admin": 3,
    "service-account": 2,
}

# Systems that are considered high-blast-radius (touching these raises score)
HIGH_BLAST_SYSTEMS = {
    # From identity_events.csv resource field
    "PROD_DB",        # production database — highest blast radius
    "Admin_Console",  # admin panel — direct system control
    "SIEM",           # security system — attacker would want to blind this first
    "Data_Lake",      # bulk data store
    "Customer_Vault", # PII / customer data
    "HRIS",           # HR sensitive data
    "GL_System",      # finance/accounting records

    # From identity_users.csv systems_access field
    "ADMIN_SYS",      # admin system access
    "AWS_IAM",        # cloud identity — if compromised, lateral movement everywhere
    "GCP",            # same reasoning
}

# Departments whose month-end spikes are expected (reduces false positives)
MONTH_END_EXEMPT_DEPTS = {"Finance", "Accounting", "Compliance"}

# Cross-dept matrix: dept → systems they legitimately own
DEPT_SYSTEM_MAP = {
    "Finance": {"GL_System", "BI_Tool", "Email_Archive"},
    "HR": {"HRIS", "File_Share"},
    "Engineering": {"PROD_DB", "Admin_Console"},
    "Security": {"SIEM", "Admin_Console"},
    "IT": {"SIEM", "Admin_Console", "PROD_DB"},
    "Legal": {"File_Share", "Email_Archive"},
    "Operations": {"PROD_DB", "BI_Tool"},
    "Support": {"Customer_Vault", "File_Share"},
    "Sales": {"Customer_Vault", "BI_Tool"},
    "Marketing": {"BI_Tool", "Customer_Vault"},
    "Executive": set(),
    "Compliance": {"GL_System", "SIEM", "Email_Archive"},
}


# ─── Timestamp Parsing ────────────────────────────────────────────────────────

def _parse_ts(ts_str: Any) -> datetime | None:
    """Parse ISO-like timestamp strings tolerantly."""
    if not ts_str or str(ts_str).strip() == "":
        return None
    s = str(ts_str).strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _is_month_end(dt: datetime) -> bool:
    """Returns True for the last 3 days of a month."""
    import calendar
    last_day = calendar.monthrange(dt.year, dt.month)[1]
    return dt.day >= last_day - 2


def _is_quarter_end(dt: datetime) -> bool:
    """Returns True for the last week of Mar, Jun, Sep, Dec."""
    return dt.month in {3, 6, 9, 12} and dt.day >= 24


# ─── Per-user Event Aggregation ───────────────────────────────────────────────

def _aggregate_user_events(
    events: list[dict[str, Any]], department: str
) -> dict[str, Any]:
    """Compute all event-derived signals for one user."""
    total = len(events)
    if total == 0:
        return {
            "event_count": 0,
            "after_hours_ratio": 0.0,
            "high_sensitivity_ratio": 0.0,
            "fail_ratio": 0.0,
            "export_count": 0,
            "admin_op_count": 0,
            "login_fail_count": 0,
            "unique_systems_per_day_max": 0,
            "cross_dept_access_ratio": 0.0,
            "month_end_spike_ratio": 0.0,
            "flagged_events": [],
        }

    after_hours = 0
    high_sens = 0
    fails = 0
    exports = 0
    admin_ops = 0
    login_fails = 0
    cross_dept = 0
    month_end = 0

    # Track unique systems per calendar day
    daily_systems: dict[str, set[str]] = defaultdict(set)

    flagged_events: list[dict[str, Any]] = []

    dept_systems = DEPT_SYSTEM_MAP.get(department, None)

    for ev in events:
        tc = str(ev.get("time_classification", "")).strip().lower()
        sensitivity = str(ev.get("resource_sensitivity", "")).strip().lower()
        status = str(ev.get("status", "")).strip().lower()
        action = str(ev.get("action", "")).strip().lower()
        resource = str(ev.get("resource", "")).strip()

        is_after_hours = tc in {"night", "unusual_hours", "weekend"}
        is_high_sens = sensitivity == "high"
        is_fail = status not in {"success", ""}
        is_export = action == "export_data"
        is_admin_op = action == "admin_operation"
        is_login_fail = action == "login" and is_fail

        if is_after_hours:
            after_hours += 1
        if is_high_sens:
            high_sens += 1
        if is_fail:
            fails += 1
        if is_export:
            exports += 1
        if is_admin_op:
            admin_ops += 1
        if is_login_fail:
            login_fails += 1

        # Cross-department access check (skip for executives / no-map depts)
        if dept_systems is not None and len(dept_systems) > 0:
            if resource and resource not in dept_systems:
                cross_dept += 1

        # Month-end / quarter-end spike
        ts = _parse_ts(ev.get("timestamp"))
        if ts:
            date_key = ts.strftime("%Y-%m-%d")
            daily_systems[date_key].add(resource)
            if _is_month_end(ts) or _is_quarter_end(ts):
                month_end += 1

        # Flag event if any signal is present
        is_flagged = (
            is_after_hours or is_high_sens or is_fail
            or is_export or is_admin_op
        )
        if is_flagged:
            flagged_events.append(ev)

    max_daily_systems = max((len(v) for v in daily_systems.values()), default=0)

    return {
        "event_count": total,
        "after_hours_ratio": after_hours / total,
        "high_sensitivity_ratio": high_sens / total,
        "fail_ratio": fails / total,
        "export_count": exports,
        "admin_op_count": admin_ops,
        "login_fail_count": login_fails,
        "unique_systems_per_day_max": max_daily_systems,
        "cross_dept_access_ratio": cross_dept / total if total else 0.0,
        "month_end_spike_ratio": month_end / total if total else 0.0,
        "flagged_events": flagged_events,
    }


# ─── User Feature Vector ──────────────────────────────────────────────────────

FEATURE_NAMES = [
    "privilege_score",          # 1–3
    "systems_count",            # how many systems the user has access to
    "days_inactive",            # days since last login
    "is_stale",                 # 1 if > 30d inactive
    "is_very_stale",            # 1 if > 90d inactive
    "is_inactive_account",      # 1 if is_active == False
    "is_new_hire",              # 1 if hired < 30d ago
    "event_count",
    "after_hours_ratio",
    "high_sensitivity_ratio",
    "fail_ratio",
    "export_count",
    "admin_op_count",
    "login_fail_count",
    "unique_systems_per_day_max",
    "cross_dept_access_ratio",
    "high_blast_system_count",
    "high_sens_after_hours",  # count of high-blast-radius systems
]


def extract_user_features(
    profile: dict[str, Any], event_agg: dict[str, Any]
) -> dict[str, float]:
    """Returns a flat float dict aligned with FEATURE_NAMES."""
    priv_level = str(profile.get("privilege_level", "user")).strip().lower()
    privilege_score = float(PRIVILEGE_SCORE.get(priv_level, 1))
    systems_access: list[str] = profile.get("systems_access", []) or []
    days_inactive = int(profile.get("days_inactive", 0) or 0)
    is_active = str(profile.get("is_active", "true")).strip().lower() == "true"

    # High-blast-radius systems the user can access
    high_blast_count = sum(
        1 for s in systems_access if s in HIGH_BLAST_SYSTEMS
    )

    cfg_stale = 30
    cfg_very_stale = 45

    return {
        "privilege_score": privilege_score,
        "systems_count": float(len(systems_access)),
        "days_inactive": float(days_inactive),
        "is_stale": 1.0 if days_inactive > cfg_stale else 0.0,
        "is_very_stale": 1.0 if days_inactive > cfg_very_stale else 0.0,
        "is_inactive_account": 0.0 if is_active else 1.0,
        "is_new_hire": 1.0 if bool(profile.get("is_new_hire", False)) else 0.0,
        "event_count": float(event_agg.get("event_count", 0)),
        "after_hours_ratio": float(event_agg.get("after_hours_ratio", 0.0)),
        "high_sensitivity_ratio": float(event_agg.get("high_sensitivity_ratio", 0.0)),
        "fail_ratio": float(event_agg.get("fail_ratio", 0.0)),
        "export_count": float(event_agg.get("export_count", 0)),
        "admin_op_count": float(event_agg.get("admin_op_count", 0)),
        "login_fail_count": float(event_agg.get("login_fail_count", 0)),
        "unique_systems_per_day_max": float(event_agg.get("unique_systems_per_day_max", 0)),
        "cross_dept_access_ratio": float(event_agg.get("cross_dept_access_ratio", 0.0)),
        "high_blast_system_count": float(high_blast_count),
        "high_sens_after_hours": float(event_agg.get("after_hours_ratio", 0.0)) 
                         * float(event_agg.get("high_sensitivity_ratio", 0.0)),
    }


def build_feature_matrix(
    profiles: list[dict[str, Any]],
    all_events: list[dict[str, Any]],
) -> tuple[np.ndarray, list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Returns:
        feature_matrix  — shape (n_users, len(FEATURE_NAMES))
        event_agg_list  — one event_agg dict per user (same order as profiles)
        event_features  — per-event feature dicts for KMeans clustering
    """
    # Index events by user_id for O(1) lookup
    user_event_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in all_events:
        uid = str(ev.get("user_id", "")).strip()
        if uid:
            user_event_index[uid].append(ev)

    rows: list[list[float]] = []
    event_agg_list: list[dict[str, Any]] = []

    for profile in profiles:
        uid = str(profile.get("user_id", "")).strip()
        dept = str(profile.get("department", "")).strip()
        user_events = user_event_index.get(uid, [])
        agg = _aggregate_user_events(user_events, dept)
        feat = extract_user_features(profile, agg)
        rows.append([feat[name] for name in FEATURE_NAMES])
        event_agg_list.append(agg)

    feature_matrix = np.array(rows, dtype=np.float64)

    # Per-event features for KMeans
    event_features = _build_event_features(all_events)

    return feature_matrix, event_agg_list, event_features


def _build_event_features(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Produces a flat feature dict per event for KMeans clustering."""
    result = []
    for ev in events:
        ts = _parse_ts(ev.get("timestamp"))
        hour = float(ts.hour) if ts else 12.0
        tc = str(ev.get("time_classification", "")).strip().lower()
        sensitivity = str(ev.get("resource_sensitivity", "")).strip().lower()
        status = str(ev.get("status", "")).strip().lower()
        action = str(ev.get("action", "")).strip().lower()

        result.append({
            "_key": f"{ev.get('timestamp', '')}|{ev.get('user_id', '')}",
            "hour_of_day": hour,
            "is_after_hours": 1.0 if tc in {"night", "unusual_hours", "weekend"} else 0.0,
            "is_high_sensitivity": 1.0 if sensitivity == "high" else 0.0,
            "is_failure": 1.0 if status not in {"success", ""} else 0.0,
            "is_admin_op": 1.0 if action == "admin_operation" else 0.0,
            "is_export": 1.0 if action == "export_data" else 0.0,
        })
    return result
