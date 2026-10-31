# ============================================================
# FILE: backend/models/breach_simulator.py
# OWNER: Person 1 — ML pipeline
# STATUS: Complete
# DEPENDS ON: schemas.py
# ============================================================
"""Simulate breach impact from a user's direct and two-hop access graph.

The first hop is the user's own systems_access list. The second hop models
simple lateral movement: if another user shares at least one accessible system
with the current user, that other user becomes a pivot target, and any systems
they can access may become reachable to the attacker as well.

The returned payload describes what the user can reach directly, what may be
reachable through shared-access pivots, which targets are high-value, and how
severe the overall data sensitivity would be if the account were compromised.
"""
from __future__ import annotations

from typing import Any


SYSTEM_SENSITIVITY: dict[str, str] = {
    "PROD_DB": "critical",
    "Admin_Console": "critical",
    "SIEM": "critical",
    "AWS_IAM": "critical",
    "ADMIN_SYS": "critical",
    "Data_Lake": "high",
    "Customer_Vault": "high",
    "HRIS": "high",
    "GL_System": "high",
    "GCP": "high",
    "Azure_AD": "high",
    "Okta": "medium",
    "Salesforce": "medium",
    "ServiceNow": "medium",
    "AD": "medium",
    "VPN": "medium",
    "EMAIL": "low",
}


def _sensitivity_rank(level: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(level, 3)


def _normalise_systems_access(profile: dict[str, Any]) -> list[str]:
    systems = profile.get("systems_access", [])
    if not isinstance(systems, list):
        return []
    return [str(system).strip() for system in systems if str(system).strip()]


def simulate_breach(
    profile: dict[str, Any],
    all_profiles: list[dict[str, Any]],
) -> dict[str, Any]:
    """Simulate direct access and two-hop lateral movement from one account.

    Output fields:
    - user_id: the account being simulated
    - directly_accessible: direct systems with sensitivity labels, sorted by
      sensitivity from critical to low
    - lateral_movement_risk: systems reachable through shared-access pivots
    - pivot_user_count: number of users that can be used as lateral movement pivots
    - pivot_user_ids: up to 10 pivot user_ids sorted by risk_score descending
    - high_value_targets: critical/high systems reachable directly or laterally
    - data_sensitivity_score: weighted score estimating impact severity
    - estimated_impact: categorical impact tier derived from the score
    """
    user_systems = _normalise_systems_access(profile)
    user_systems_set = set(user_systems)

    directly_accessible = [
        {
            "system": system,
            "sensitivity": SYSTEM_SENSITIVITY.get(system, "low"),
        }
        for system in user_systems
    ]
    directly_accessible.sort(key=lambda item: (_sensitivity_rank(item["sensitivity"]), item["system"]))

    pivot_targets: list[dict[str, Any]] = []
    pivot_user_ids: list[tuple[str, float]] = []
    lateral_systems_set: set[str] = set()

    for other in all_profiles:
        other_user_id = str(other.get("user_id", "")).strip()
        if not other_user_id or other_user_id == str(profile.get("user_id", "")).strip():
            continue

        other_systems = set(_normalise_systems_access(other))
        if not (other_systems & user_systems_set):
            continue

        pivot_targets.append(other)
        pivot_user_ids.append((other_user_id, float(other.get("risk_score", 0.0) or 0.0)))
        lateral_systems_set.update(other_systems)

    lateral_systems_set -= user_systems_set
    lateral_systems = sorted(lateral_systems_set)

    high_value_targets = sorted(
        {
            system
            for system in (user_systems_set | lateral_systems_set)
            if SYSTEM_SENSITIVITY.get(system, "low") in {"critical", "high"}
        }
    )

    direct_critical = sum(1 for system in user_systems if SYSTEM_SENSITIVITY.get(system, "low") == "critical")
    direct_high = sum(1 for system in user_systems if SYSTEM_SENSITIVITY.get(system, "low") == "high")
    lateral_count = len(lateral_systems)
    pivot_count = len(pivot_targets)

    raw_score = (direct_critical * 30) + (direct_high * 15) + (lateral_count * 3) + (pivot_count * 2)
    data_sensitivity_score = round(min(raw_score, 100.0), 2)

    if data_sensitivity_score >= 75:
        estimated_impact = "CATASTROPHIC"
    elif data_sensitivity_score >= 50:
        estimated_impact = "SEVERE"
    elif data_sensitivity_score >= 25:
        estimated_impact = "MODERATE"
    else:
        estimated_impact = "LOW"

    pivot_user_ids_sorted = [
        user_id
        for user_id, _score in sorted(pivot_user_ids, key=lambda item: item[1], reverse=True)[:10]
    ]

    return {
        "user_id": profile["user_id"],
        "directly_accessible": directly_accessible,
        "lateral_movement_risk": lateral_systems,
        "pivot_user_count": pivot_count,
        "pivot_user_ids": pivot_user_ids_sorted,
        "high_value_targets": high_value_targets,
        "data_sensitivity_score": data_sensitivity_score,
        "estimated_impact": estimated_impact,
    }


def summarise_for_prompt(breach_sim: dict[str, Any]) -> str:
    """Returns a compact plain-text summary of a breach simulation result
    suitable for injection into an LLM prompt.
    Keeps token count low while preserving the most critical signals.
    """
    estimated_impact = str(breach_sim.get("estimated_impact", "LOW"))
    data_sensitivity_score = float(breach_sim.get("data_sensitivity_score", 0.0) or 0.0)
    high_value_targets = [str(system) for system in breach_sim.get("high_value_targets", []) if str(system).strip()]
    lateral_movement_risk = [str(system) for system in breach_sim.get("lateral_movement_risk", []) if str(system).strip()]
    pivot_user_count = int(breach_sim.get("pivot_user_count", 0) or 0)

    direct_critical = [
        str(item.get("system", ""))
        for item in breach_sim.get("directly_accessible", [])
        if isinstance(item, dict) and str(item.get("sensitivity", "")).strip().lower() == "critical" and str(item.get("system", "")).strip()
    ]

    lines = [
        "BREACH SIMULATION CONTEXT:",
        f"  Estimated impact:        {estimated_impact}",
        f"  Data sensitivity score:  {data_sensitivity_score:.1f} / 100",
        f"  High value targets:      {', '.join(high_value_targets) if high_value_targets else 'None'}",
        f"  Lateral systems reached: {', '.join(lateral_movement_risk) if lateral_movement_risk else 'None'} (via {pivot_user_count} pivot users)",
        f"  Direct critical systems: {', '.join(direct_critical) if direct_critical else 'None'}",
    ]
    return "\n".join(lines)