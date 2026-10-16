from __future__ import annotations

from typing import Any


def _always_false(_profile: dict[str, Any], _events: list[dict[str, Any]]) -> tuple[bool, str]:
    return False, ""


# Separation of Duties violation detection.
# Real rules are intentionally stubbed here so the two developers can implement them later.
SOD_RULES = [
    {
        "rule_id": "SOD-001",
        "description": "Admin privilege plus export on high-sensitivity resources.",
        "condition_fn": _always_false,
    },
    {
        "rule_id": "SOD-002",
        "description": "Admin operation and export_data in the same one-hour session.",
        "condition_fn": _always_false,
    },
    {
        "rule_id": "SOD-003",
        "description": "Service account performing interactive login events.",
        "condition_fn": _always_false,
    },
    {
        "rule_id": "SOD-004",
        "description": "Access to more than five distinct systems in a single day.",
        "condition_fn": _always_false,
    },
]


def check_sod_violations(profile: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Runs the stubbed SoD rule list and stamps the profile with any matches."""
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
