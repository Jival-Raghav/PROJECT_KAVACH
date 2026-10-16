"""
models/sod_violations.py
Real Separation-of-Duties violation detection.
All four SOD rules fully implemented — no _always_false stubs.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

#  Helpers

def _parse_ts(ts_str: Any) -> datetime | None:
    if not ts_str or str(ts_str).strip() == "":
        return None
    s = str(ts_str).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


#  SOD Rule Implementations

def _sod_001(profile: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, str]:
    """SOD-001: Admin privilege + export_data on high-sensitivity resources."""
    priv = str(profile.get("privilege_level", "")).strip().lower()
    if priv not in {"admin", "power-user"}:
        return False, ""

    violations = [
        ev for ev in events
        if str(ev.get("action", "")).strip().lower() == "export_data"
        and str(ev.get("resource_sensitivity", "")).strip().lower() == "high"
    ]
    if violations:
        resources = list({str(ev.get("resource", "")) for ev in violations})
        return True, (
            f"Admin/power-user performed {len(violations)} high-sensitivity export(s) "
            f"on: {', '.join(resources[:5])}."
        )
    return False, ""


def _sod_002(profile: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, str]:
    """SOD-002: admin_operation + export_data within the same 60-minute window."""
    from collections import defaultdict

    # Group events into 1-hour buckets keyed by (date, hour)
    hourly_actions: dict[tuple[str, int], list[str]] = defaultdict(list)
    for ev in events:
        ts = _parse_ts(ev.get("timestamp"))
        if ts is None:
            continue
        bucket = (ts.strftime("%Y-%m-%d"), ts.hour)
        hourly_actions[bucket].append(str(ev.get("action", "")).strip().lower())

    for bucket, actions in hourly_actions.items():
        if "admin_operation" in actions and "export_data" in actions:
            date_str, hour = bucket
            return True, (
                f"admin_operation and export_data both occurred in the "
                f"{hour:02d}:00–{hour:02d}:59 window on {date_str}."
            )
    return False, ""


def _sod_003(profile: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, str]:
    """SOD-003: Service account performing interactive login events."""
    priv = str(profile.get("privilege_level", "")).strip().lower()
    if priv != "service-account":
        return False, ""

    login_events = [
        ev for ev in events
        if str(ev.get("action", "")).strip().lower() == "login"
    ]
    if login_events:
        timestamps = [str(ev.get("timestamp", "")) for ev in login_events[:3]]
        return True, (
            f"Service account performed {len(login_events)} interactive login(s). "
            f"First occurrences: {', '.join(timestamps)}."
        )
    return False, ""


def _sod_004(profile: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, str]:
    """SOD-004: Access to more than 5 distinct systems in a single calendar day."""
    # Group distinct resources per day
    daily_systems: dict[str, set[str]] = defaultdict(set)
    for ev in events:
        ts = _parse_ts(ev.get("timestamp"))
        resource = str(ev.get("resource", "")).strip()
        if ts and resource:
            daily_systems[ts.strftime("%Y-%m-%d")].add(resource)

    for date_str, systems in daily_systems.items():
        if len(systems) > 5:
            return True, (
                f"Accessed {len(systems)} distinct systems on {date_str}: "
                f"{', '.join(list(systems)[:7])}{'...' if len(systems) > 7 else ''}."
            )
    return False, ""


#  Rule Registry 

SOD_RULES = [
    {
        "rule_id": "SOD-001",
        "description": "Admin privilege plus export on high-sensitivity resources.",
        "condition_fn": _sod_001,
    },
    {
        "rule_id": "SOD-002",
        "description": "Admin operation and export_data in the same one-hour session.",
        "condition_fn": _sod_002,
    },
    {
        "rule_id": "SOD-003",
        "description": "Service account performing interactive login events.",
        "condition_fn": _sod_003,
    },
    {
        "rule_id": "SOD-004",
        "description": "Access to more than five distinct systems in a single day.",
        "condition_fn": _sod_004,
    },
]


def check_sod_violations(
    profile: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Runs all SoD rules and stamps the profile with any matches."""
    violations: list[dict[str, Any]] = []
    for rule in SOD_RULES:
        triggered, explanation = rule["condition_fn"](profile, events)
        if triggered:
            violations.append(
                {
                    "rule_id": rule["rule_id"],
                    "description": rule["description"],
                    "explanation": explanation,
                    "severity": "HIGH",
                }
            )
    profile["sod_violations"] = violations
    return violations
