
# ============================================================

# FILE: backend/models/breach_simulator.py

# OWNER: Person 1 — ML pipeline

# STATUS: Fixed (2025-06 — CATASTROPHIC inflation bug)

# DEPENDS ON: schemas.py

# ============================================================

"""Simulate breach impact from a user's direct and two-hop access graph.



The first hop is the user's own systems_access list. The second hop models

simple lateral movement: if another user shares at least one PRIVILEGED system

with the current user AND has higher privilege or different department access,

that user is a meaningful pivot target.



Fix: The original formula gave (pivot_count * 2) + (lateral_count * 3) using

a naive "shares any system" pivot definition over 300 users — this caused

every user to score 100/100 CATASTROPHIC because nearly everyone shares at

least one system (AD, EMAIL, VPN). The fix:



1. Pivot = only users who share a CRITICAL or HIGH sensitivity system

   (not low/medium noise systems like AD, EMAIL, VPN).

2. lateral_movement_risk = only systems reachable via those meaningful pivots

   that are themselves CRITICAL or HIGH (not every system the pivot accesses).

3. Scoring: base is still driven by direct access; lateral contribution is

   capped at 20 points max and pivot contribution at 10 points max so direct

   access patterns dominate.

4. pivot_user_count is renamed semantically: it counts meaningful pivot

   targets (shared privileged access), not all co-users.

"""

from __future__ import annotations



from typing import Any





SYSTEM_SENSITIVITY: dict[str, str] = {

    "PROD_DB":        "critical",

    "Admin_Console":  "critical",

    "SIEM":           "critical",

    "AWS_IAM":        "critical",

    "ADMIN_SYS":      "critical",

    "Data_Lake":      "high",

    "Customer_Vault": "high",

    "HRIS":           "high",

    "GL_System":      "high",

    "GCP":            "high",

    "Azure_AD":       "high",

    "Okta":           "medium",

    "Salesforce":     "medium",

    "ServiceNow":     "medium",

    "AD":             "medium",

    "VPN":            "medium",

    "EMAIL":          "low",

}



# Only systems at these levels count as meaningful pivot overlap.

# Sharing EMAIL or AD with someone is not a lateral-movement risk.

_PIVOT_SENSITIVITY_THRESHOLD = {"critical", "high"}





def _sensitivity_rank(level: str) -> int:

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    return order.get(level, 3)





def _normalise_systems_access(profile: dict[str, Any]) -> list[str]:

    systems = profile.get("systems_access", [])

    if not isinstance(systems, list):

        return []

    return [str(system).strip() for system in systems if str(system).strip()]





def _privileged_systems(sys_list: list[str]) -> set[str]:

    """Return only critical/high systems from a list."""

    return {s for s in sys_list if SYSTEM_SENSITIVITY.get(s, "low") in _PIVOT_SENSITIVITY_THRESHOLD}





def simulate_breach(

    profile: dict[str, Any],

    all_profiles: list[dict[str, Any]],

) -> dict[str, Any]:

    """Simulate direct access and two-hop lateral movement from one account.



    Output fields:

    - user_id: the account being simulated

    - directly_accessible: direct systems with sensitivity labels, sorted by

      sensitivity from critical to low

    - lateral_movement_risk: HIGH/CRITICAL systems reachable through privileged

      shared-access pivots (not every system every co-user can touch)

    - pivot_user_count: number of other users who share at least one

      CRITICAL/HIGH system with this user (meaningful pivot targets)

    - pivot_user_ids: up to 10 pivot user_ids sorted by risk_score descending

    - high_value_targets: critical/high systems reachable directly or laterally

    - data_sensitivity_score: weighted score 0–100 estimating impact severity

    - estimated_impact: categorical impact tier derived from the score

    """

    user_systems = _normalise_systems_access(profile)

    user_systems_set = set(user_systems)

    user_privileged = _privileged_systems(user_systems)



    directly_accessible = [

        {

            "system": system,

            "sensitivity": SYSTEM_SENSITIVITY.get(system, "low"),

        }

        for system in user_systems

    ]

    directly_accessible.sort(

        key=lambda item: (_sensitivity_rank(item["sensitivity"]), item["system"])

    )



    pivot_targets: list[dict[str, Any]] = []

    pivot_user_ids: list[tuple[str, float]] = []

    lateral_privileged_set: set[str] = set()   # only critical/high lateral systems



    for other in all_profiles:

        other_user_id = str(other.get("user_id", "")).strip()

        if not other_user_id or other_user_id == str(profile.get("user_id", "")).strip():

            continue



        other_systems = _normalise_systems_access(other)

        other_privileged = _privileged_systems(other_systems)



        # Only count as a pivot if they share a PRIVILEGED system with us

        if not (other_privileged & user_privileged):

            continue



        pivot_targets.append(other)

        pivot_user_ids.append(

            (other_user_id, float(other.get("risk_score", 0.0) or 0.0))

        )

        # Lateral reach = only their PRIVILEGED systems we don't already have

        lateral_privileged_set.update(other_privileged - user_systems_set)



    lateral_systems = sorted(lateral_privileged_set)



    high_value_targets = sorted(

        {

            system

            for system in (user_systems_set | lateral_privileged_set)

            if SYSTEM_SENSITIVITY.get(system, "low") in {"critical", "high"}

        }

    )



    direct_critical = sum(

        1 for s in user_systems if SYSTEM_SENSITIVITY.get(s, "low") == "critical"

    )

    direct_high = sum(

        1 for s in user_systems if SYSTEM_SENSITIVITY.get(s, "low") == "high"

    )

    lateral_critical = sum(

        1 for s in lateral_systems if SYSTEM_SENSITIVITY.get(s, "low") == "critical"

    )

    lateral_high = sum(

        1 for s in lateral_systems if SYSTEM_SENSITIVITY.get(s, "low") == "high"

    )

    pivot_count = len(pivot_targets)



    # Score: direct access dominates (max ~100 from direct alone if user has

    # 3+ critical systems). Lateral adds at most 20 pts, pivots at most 10 pts.

    direct_score  = (direct_critical * 25) + (direct_high * 10)

    lateral_score = min((lateral_critical * 8) + (lateral_high * 4), 20)

    pivot_score   = min(pivot_count * 2, 10)



    raw_score = direct_score + lateral_score + pivot_score

    data_sensitivity_score = round(min(raw_score, 100.0), 2)



    if data_sensitivity_score >= 75:

        estimated_impact = "CATASTROPHIC"

    elif data_sensitivity_score >= 45:

        estimated_impact = "SEVERE"

    elif data_sensitivity_score >= 20:

        estimated_impact = "MODERATE"

    else:

        estimated_impact = "LOW"



    pivot_user_ids_sorted = [

        user_id

        for user_id, _score in sorted(

            pivot_user_ids, key=lambda item: item[1], reverse=True

        )[:10]

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

    """

    estimated_impact       = str(breach_sim.get("estimated_impact", "LOW"))

    data_sensitivity_score = float(breach_sim.get("data_sensitivity_score", 0.0) or 0.0)

    high_value_targets     = [str(s) for s in breach_sim.get("high_value_targets", []) if str(s).strip()]

    lateral_movement_risk  = [str(s) for s in breach_sim.get("lateral_movement_risk", []) if str(s).strip()]

    pivot_user_count       = int(breach_sim.get("pivot_user_count", 0) or 0)



    direct_critical = [

        str(item.get("system", ""))

        for item in breach_sim.get("directly_accessible", [])

        if isinstance(item, dict)

        and str(item.get("sensitivity", "")).strip().lower() == "critical"

        and str(item.get("system", "")).strip()

    ]



    lines = [

        "BREACH SIMULATION CONTEXT:",

        f"  Estimated impact:        {estimated_impact}",

        f"  Data sensitivity score:  {data_sensitivity_score:.1f} / 100",

        f"  High value targets:      {', '.join(high_value_targets) if high_value_targets else 'None'}",

        f"  Lateral systems reached: {', '.join(lateral_movement_risk) if lateral_movement_risk else 'None'} (via {pivot_user_count} privileged pivot users)",

        f"  Direct critical systems: {', '.join(direct_critical) if direct_critical else 'None'}",

    ]

    return "\n".join(lines)
