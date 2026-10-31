"""
models/compliance.py
Real compliance gap checks for NIST AC-2, GDPR Art.32, NIST AC-6.
All _always_false stubs replaced with actual logic.
"""
from __future__ import annotations

from typing import Any


#  Check Implementations

def _check_nist_ac2(profile: dict[str, Any]) -> tuple[bool, str]:
    """
    NIST AC-2 Account Management:
    Account flagged if is_active=False but has had activity in the last 30 days
    OR if admin account has been inactive >30 days without deprovisioning.
    """
    is_active = bool(profile.get("is_active", True))
    days_inactive = int(profile.get("days_inactive", 0) or 0)
    priv = str(profile.get("privilege_level", "user")).strip().lower()
    event_count = int(profile.get("event_count", 0) or 0)

    # Case 1: Disabled account still showing event activity
    if not is_active and event_count > 0:
        return True, (
            f"Account is marked inactive (is_active=False) but has {event_count} "
            f"recorded access events. NIST AC-2 requires immediate review and "
            f"deprovisioning of inactive accounts."
        )

    # Case 2: Admin account stale >30 days (privilege not revoked)
    if priv == "admin" and days_inactive > 30:
        return True, (
            f"Privileged account (admin) has been inactive for {days_inactive} days "
            f"without privilege revocation. NIST AC-2 requires timely removal of "
            f"access for inactive privileged accounts."
        )

    return False, ""


def _check_gdpr_art32(profile: dict[str, Any]) -> tuple[bool, str]:
    """
    GDPR Article 32 – Security of Processing:
    Proxy check: high fail_ratio on high-sensitivity resources suggests
    unauthorised access attempts against sensitive data.
    """
    fail_ratio = float(profile.get("fail_ratio", 0.0) or 0.0)
    high_sens_ratio = float(profile.get("high_sensitivity_ratio", 0.0) or 0.0)
    login_fails = int(profile.get("login_fail_count", 0) or 0)

    # Suspicious pattern: multiple login failures + high-sensitivity resource access
    if fail_ratio > 0.25 and high_sens_ratio > 0.30 and login_fails > 2:
        return True, (
            f"High failure rate ({fail_ratio:.0%}) combined with significant "
            f"high-sensitivity resource access ({high_sens_ratio:.0%}) and "
            f"{login_fails} login failures. GDPR Art. 32 requires appropriate "
            f"technical measures to ensure data confidentiality."
        )

    return False, ""


def _check_nist_ac6(profile: dict[str, Any]) -> tuple[bool, str]:
    """
    NIST AC-6 Least Privilege:
    User has privilege level significantly exceeding what their department/role requires,
    evidenced by broad system access and admin operations without corresponding job title.
    """
    priv = str(profile.get("privilege_level", "user")).strip().lower()
    systems: list[str] = profile.get("systems_access", []) or []
    job_title = str(profile.get("job_title", "")).strip().lower()
    admin_op_count = int(profile.get("admin_op_count", 0) or 0)
    dept = str(profile.get("department", "")).strip().lower()

    # Admin roles legitimately have broad access
    admin_roles = {"administrator", "admin", "manager", "director", "vp",
                   "chief", "cto", "ciso", "ceo", "cfo", "head", "lead"}
    is_admin_role = any(role in job_title for role in admin_roles)

    # Flag: admin privilege on a clearly non-admin role performing admin ops
    if priv == "admin" and not is_admin_role and admin_op_count > 0 and len(systems) > 5:
        return True, (
            f"Account holds 'admin' privilege level with access to {len(systems)} "
            f"systems and {admin_op_count} admin operations, but job title "
            f"('{profile.get('job_title', 'unknown')}') suggests a standard "
            f"contributor role. NIST AC-6 requires least-privilege access."
        )

    return False, ""


#  Control Registry 

COMPLIANCE_CONTROLS = [
    {
        "framework": "NIST",
        "control_id": "AC-2",
        "control_name": "Account Management",
        "check_fn": _check_nist_ac2,
    },
    {
        "framework": "GDPR",
        "control_id": "Art. 32",
        "control_name": "Security of Processing",
        "check_fn": _check_gdpr_art32,
    },
    {
        "framework": "NIST",
        "control_id": "AC-6",
        "control_name": "Least Privilege",
        "check_fn": _check_nist_ac6,
    },
]


def compute_compliance_gaps(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Runs all compliance controls and stamps the profile with any gaps."""
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
                    "severity": "HIGH" if "admin" in gap_description.lower() else "MEDIUM",
                }
            )
    profile["compliance_gaps"] = gaps
    return gaps
