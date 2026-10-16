from __future__ import annotations

from collections import defaultdict
from statistics import pstdev
from typing import Any


def compute_department_baselines(profiles: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Computes per-department averages for the core dashboard baseline metrics."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for profile in profiles:
        grouped[str(profile.get("department", "Unknown"))].append(profile)

    baselines: dict[str, dict[str, Any]] = {}
    for department, members in grouped.items():
        count = len(members)
        baselines[department] = {
            "avg_risk_score": sum(float(member.get("risk_score", 0.0) or 0.0) for member in members) / count if count else 0.0,
            "avg_after_hours_ratio": sum(float(member.get("after_hours_ratio", 0.0) or 0.0) for member in members) / count if count else 0.0,
            "avg_export_count": sum(float(member.get("export_count", 0) or 0) for member in members) / count if count else 0.0,
            "member_count": count,
        }
    return baselines


def detect_org_anomalies(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compares each user to the department baseline and stamps the org_anomaly field."""
    baselines = compute_department_baselines(profiles)
    grouped: dict[str, list[float]] = defaultdict(list)
    for profile in profiles:
        grouped[str(profile.get("department", "Unknown"))].append(float(profile.get("risk_score", 0.0) or 0.0))

    for profile in profiles:
        department = str(profile.get("department", "Unknown"))
        dept_baseline = baselines.get(department, {"avg_risk_score": 0.0, "avg_after_hours_ratio": 0.0, "avg_export_count": 0.0, "member_count": 0})
        risk_values = grouped.get(department, [])
        stddev = pstdev(risk_values) if len(risk_values) > 1 else 0.0
        threshold = float(dept_baseline.get("avg_risk_score", 0.0)) + (2 * stddev)
        is_anomaly = float(profile.get("risk_score", 0.0) or 0.0) > threshold if risk_values else False
        reason = (
            f"Risk score {float(profile.get('risk_score', 0.0) or 0.0):.1f} is more than 2 std deviations above the {department} department average."
            if is_anomaly
            else ""
        )
        profile["org_anomaly"] = {
            "is_anomaly": is_anomaly,
            "reason": reason,
            "dept_baseline": dept_baseline,
        }
    return profiles
