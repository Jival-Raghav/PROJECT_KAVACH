from __future__ import annotations

import random
from typing import Any


def compute_user_features(user_profile: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Computes a flat feature dictionary from a user profile and that user's events."""
    total_events = len(events)
    after_hours_events = sum(
        1
        for event in events
        if str(event.get("time_classification", "")).strip().lower() in {"night", "unusual_hours", "weekend"}
    )
    high_sensitivity_events = sum(
        1 for event in events if str(event.get("resource_sensitivity", "")).strip().lower() == "high"
    )
    fail_events = sum(1 for event in events if str(event.get("status", "")).strip().lower() != "success")
    admin_op_count = sum(1 for event in events if str(event.get("action", "")).strip().lower() == "admin_operation")
    export_count = sum(1 for event in events if str(event.get("action", "")).strip().lower() == "export_data")

    privilege_map = {
        "user": 1,
        "power-user": 2,
        "admin": 3,
        "service-account": 2,
    }

    return {
        "privilege_score": privilege_map.get(str(user_profile.get("privilege_level", "user")).strip().lower(), 1),
        "systems_count": len(user_profile.get("systems_access", []) or []),
        "days_inactive": int(user_profile.get("days_inactive", 0) or 0),
        "event_count": total_events,
        "after_hours_ratio": after_hours_events / total_events if total_events else 0.0,
        "high_sensitivity_ratio": high_sensitivity_events / total_events if total_events else 0.0,
        "fail_ratio": fail_events / total_events if total_events else 0.0,
        "admin_op_count": admin_op_count,
        "export_count": export_count,
    }


def score_users(profiles: list[dict[str, Any]], all_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Updates each profile with stubbed model outputs while keeping the feature calculations real."""
    for profile in profiles:
        user_events = [event for event in all_events if str(event.get("user_id", "")) == str(profile.get("user_id", ""))]
        features = compute_user_features(profile, user_events)
        profile["risk_score"] = round(random.uniform(20.0, 95.0), 2)
        profile["anomaly_score_raw"] = 0.0
        profile["event_count"] = features["event_count"]
        profile["after_hours_ratio"] = features["after_hours_ratio"]
        profile["high_sensitivity_ratio"] = features["high_sensitivity_ratio"]
        profile["fail_ratio"] = features["fail_ratio"]
        profile["export_count"] = features["export_count"]
        profile["admin_op_count"] = features["admin_op_count"]
        profile["flagged_events"] = [
            event
            for event in user_events
            if str(event.get("time_classification", "")).strip().lower() in {"night", "unusual_hours", "weekend"}
            or str(event.get("resource_sensitivity", "")).strip().lower() == "high"
            or str(event.get("status", "")).strip().lower() != "success"
            or str(event.get("action", "")).strip().lower() in {"export_data", "admin_operation"}
        ]
        profile.setdefault("flags", [])
    return profiles
