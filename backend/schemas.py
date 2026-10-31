# THIS FILE IS THE CONTRACT. DO NOT CHANGE FIELD NAMES OR TYPES WITHOUT UPDATING ALL OTHER FILES.

from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, timedelta
from typing import Any, TypedDict


class NarrativePayload(TypedDict):
    prosecution: str  # LLM-generated accusation with evidence.
    devils_advocate: str  # LLM-generated challenge to the accusation.
    doubt_score: float  # 0.0 (certain threat) to 1.0 (almost certainly benign).
    final_severity: str  # "CRITICAL" | "HIGH" | "REVIEW" | "INFORMATIONAL" | "SUPPRESSED".
    recommendation: str  # Actionable step for analysts.
    breach_impact: str  # If compromised, what systems or data are at risk.


class OrgAnomalyPayload(TypedDict):
    is_anomaly: bool  # True when the user's profile is far outside the department baseline.
    reason: str  # Human-readable explanation of the anomaly decision.
    dept_baseline: dict[str, Any]  # Department baseline metrics used for comparison.


class UserRiskProfile(TypedDict):
    user_id: str  # Unique identity key from identity_users.csv, e.g. "USR00045".
    username: str  # Login or display username, e.g. "pooja.murphy".
    email: str  # Corporate email address.
    department: str  # Department label, e.g. "Finance" or "Engineering".
    job_title: str  # User's job title from the HR feed.
    privilege_level: str  # Access tier: "user" | "power-user" | "admin" | "service-account".
    systems_access: list[str]  # Systems this user can access, split from the pipe-separated CSV field.
    last_login: str  # ISO date string for the most recent login.
    days_inactive: int  # Number of days since the last login.
    is_active: bool  # True if the account is active.
    hire_date: str  # ISO date string for the hire date.
    is_new_hire: bool  # True if hired within the last 30 days.
    risk_score: float  # 0.0 to 100.0; higher means riskier.
    anomaly_score_raw: float  # Raw Isolation Forest score before normalization.
    cluster_label: int  # KMeans cluster identifier.
    cluster_description: str  # Human-readable label for the event cluster.
    flags: list[str]  # Rule and model flag codes for this user.
    sod_violations: list[dict[str, Any]]  # Separation-of-duties violation objects.
    compliance_gaps: list[dict[str, Any]]  # Compliance gap objects.
    org_anomaly: OrgAnomalyPayload  # Department-level anomaly context.
    event_count: int  # Total events associated with the user.
    flagged_events: list[dict[str, Any]]  # Event rows that triggered one or more flags.
    after_hours_ratio: float  # Fraction of events outside normal business hours.
    high_sensitivity_ratio: float  # Fraction of events against high-sensitivity resources.
    fail_ratio: float  # Fraction of events with failure status.
    export_count: int  # Number of export-style events.
    admin_op_count: int  # Number of admin-operation events.
    narrative: NarrativePayload | None  # Cached LLM narrative, or None until generated.
    suppressed: bool  # True if an analyst marked the profile as a false positive.
    feedback_note: str  # Optional analyst note associated with suppression or review.


def empty_narrative() -> dict[str, Any]:
    return {
        "prosecution": "",
        "devils_advocate": "",
        "doubt_score": 0.5,
        "final_severity": "",
        "recommendation": "",
        "breach_impact": "",
    }


USER_RISK_PROFILE_TEMPLATE: dict[str, Any] = {
    "user_id": "",
    "username": "",
    "email": "",
    "department": "",
    "job_title": "",
    "privilege_level": "user",
    "systems_access": [],
    "last_login": "",
    "days_inactive": 0,
    "is_active": False,
    "hire_date": "",
    "is_new_hire": False,
    "risk_score": 50.0,
    "anomaly_score_raw": 0.0,
    "cluster_label": 0,
    "cluster_description": "Unclustered",
    "flags": [],
    "sod_violations": [],
    "compliance_gaps": [],
    "org_anomaly": {"is_anomaly": False, "reason": "", "dept_baseline": {}},
    "event_count": 0,
    "flagged_events": [],
    "after_hours_ratio": 0.0,
    "high_sensitivity_ratio": 0.0,
    "fail_ratio": 0.0,
    "export_count": 0,
    "admin_op_count": 0,
    "narrative": None,
    "suppressed": False,
    "feedback_note": "",
}

USER_RISK_PROFILE_JSON_TEMPLATE: dict[str, Any] = deepcopy(USER_RISK_PROFILE_TEMPLATE)


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "active"}


def _parse_systems_access(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    return [item.strip() for item in text.split("|") if item.strip()]


def _is_new_hire(hire_date: str) -> bool:
    try:
        parsed_hire = datetime.fromisoformat(str(hire_date)).date()
    except ValueError:
        try:
            parsed_hire = date.fromisoformat(str(hire_date))
        except ValueError:
            return False
    return date.today() - parsed_hire <= timedelta(days=30)


def make_stub_profile(user_row: dict[str, Any]) -> dict[str, Any]:
    systems_access = _parse_systems_access(user_row.get("systems_access"))
    hire_date = str(user_row.get("hire_date", ""))

    profile: dict[str, Any] = deepcopy(USER_RISK_PROFILE_TEMPLATE)
    profile.update(
        {
            "user_id": str(user_row.get("user_id", "")),
            "username": str(user_row.get("username", "")),
            "email": str(user_row.get("email", "")),
            "department": str(user_row.get("department", "")),
            "job_title": str(user_row.get("job_title", "")),
            "privilege_level": str(user_row.get("privilege_level", "user")),
            "systems_access": systems_access,
            "last_login": str(user_row.get("last_login", "")),
            "days_inactive": int(user_row.get("days_inactive", 0) or 0),
            "is_active": _parse_bool(user_row.get("is_active")),
            "hire_date": hire_date,
            "is_new_hire": _is_new_hire(hire_date),
            "risk_score": 50.0,
            "anomaly_score_raw": 0.0,
            "cluster_label": 0,
            "cluster_description": "Unclustered",
            "flags": [],
            "sod_violations": [],
            "compliance_gaps": [],
            "org_anomaly": {"is_anomaly": False, "reason": "", "dept_baseline": {}},
            "event_count": 0,
            "flagged_events": [],
            "after_hours_ratio": 0.0,
            "high_sensitivity_ratio": 0.0,
            "fail_ratio": 0.0,
            "export_count": 0,
            "admin_op_count": 0,
            "narrative": None,
            "suppressed": False,
            "feedback_note": "",
        }
    )
    return profile
