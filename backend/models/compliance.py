from __future__ import annotations

from typing import Any


def _always_false(_profile: dict[str, Any]) -> tuple[bool, str]:
    return False, ""


# Compliance controls are stubbed so the contract exists before the real logic is added.
COMPLIANCE_CONTROLS = [
    {
        "framework": "NIST",
        "control_id": "AC-2",
        "control_name": "Account Management",
        "check_fn": _always_false,
    },
    {
        "framework": "GDPR",
        "control_id": "Art. 32",
        "control_name": "Security of Processing",
        "check_fn": _always_false,
    },
    {
        "framework": "NIST",
        "control_id": "AC-6",
        "control_name": "Least Privilege",
        "check_fn": _always_false,
    },
]


def compute_compliance_gaps(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Runs the stubbed compliance controls and stamps the profile with any gaps."""
    gaps: list[dict[str, Any]] = []
    for control in COMPLIANCE_CONTROLS:
        violated, gap_description = control["check_fn"](profile)
        if violated:
            gaps.append(
                {
                    "framework": control["framework"],
                    "control_id": control["control_id"],
                    "control_name": control["control_name"],
                    "gap": gap_description,
                    "severity": "MEDIUM",
                }
            )
    profile["compliance_gaps"] = gaps
    return gaps
