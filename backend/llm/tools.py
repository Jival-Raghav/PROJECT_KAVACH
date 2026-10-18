"""backend/llm/tools.py
Deterministic Evidence Verification Tools for Phase 4 Devil's Advocate Co-Pilot.

Provides read-only, evidence-grounded queries over CanonicalBundle and OrgContext:
1. was_on_call: Validates active on-call schedule covering an alert timestamp.
2. leave_overlap: Checks if an employee was on approved leave during access.
3. change_ticket_covering: Checks active, approved change tickets covering a system and time.
4. project_membership: Verifies cross-department project access authorizations.
5. recent_role_change: Checks recent promotions or departmental transfers within N days.
6. approved_exception: Verifies documented security exemptions approved by Security/CISO.
7. peer_comparison: Compares individual metric against peer cohort distribution.
8. own_history_baseline: Compares metric against user's historical 30-day baseline.
9. is_privileged_by_title: Semantic check on job title privilege expectations.
10. service_account_owner: Retrieves assigned human custodian for non-human accounts.

Enforces strict Pydantic argument-schema validation before execution.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from core.models import CanonicalBundle
from detect.features import parse_iso_dt
from pydantic import BaseModel, Field, ValidationError

# ── Argument Schemas for Strict Validation ────────────────────────────────────


class WasOnCallArgs(BaseModel):
    user: str = Field(..., description="Target user identifier or email")
    ts: str = Field(..., description="ISO 8601 timestamp of flagged event")
    system: str | None = Field(default=None, description="Optional target system name")


class LeaveOverlapArgs(BaseModel):
    user: str = Field(..., description="Target user identifier or email")
    ts: str = Field(..., description="ISO 8601 timestamp of flagged event")


class ChangeTicketCoveringArgs(BaseModel):
    user: str = Field(..., description="Target user identifier or email")
    system: str = Field(..., description="Target system accessed")
    ts: str = Field(..., description="ISO 8601 timestamp of access")


class ProjectMembershipArgs(BaseModel):
    user: str = Field(..., description="Target user identifier or email")
    system: str = Field(..., description="System accessed")
    ts: str | None = Field(default=None, description="Optional access timestamp")


class RecentRoleChangeArgs(BaseModel):
    user: str = Field(..., description="Target user identifier or email")
    ts: str = Field(..., description="Event timestamp")
    window_days: int = Field(default=60, ge=1, le=365, description="Search window in days")


class ApprovedExceptionArgs(BaseModel):
    user: str = Field(..., description="Target user identifier or email")
    entitlement: str = Field(..., description="Privileged entitlement name")
    ts: str | None = Field(default=None, description="Optional reference timestamp")


class PeerComparisonArgs(BaseModel):
    user: str = Field(..., description="Target user identifier")
    feature: str = Field(..., description="Feature to compare, e.g. 'after_hours_ratio' or 'distinct_systems'")


class OwnHistoryBaselineArgs(BaseModel):
    user: str = Field(..., description="Target user identifier")
    feature: str = Field(..., description="Feature to evaluate against 30d baseline")


class IsPrivilegedByTitleArgs(BaseModel):
    job_title: str = Field(..., description="Job title string")


class ServiceAccountOwnerArgs(BaseModel):
    account: str = Field(..., description="Account identifier or username")


TOOL_SCHEMAS: dict[str, type[BaseModel]] = {
    "was_on_call": WasOnCallArgs,
    "leave_overlap": LeaveOverlapArgs,
    "change_ticket_covering": ChangeTicketCoveringArgs,
    "project_membership": ProjectMembershipArgs,
    "recent_role_change": RecentRoleChangeArgs,
    "approved_exception": ApprovedExceptionArgs,
    "peer_comparison": PeerComparisonArgs,
    "own_history_baseline": OwnHistoryBaselineArgs,
    "is_privileged_by_title": IsPrivilegedByTitleArgs,
    "service_account_owner": ServiceAccountOwnerArgs,
}

TOOL_METADATA = [
    {
        "name": "was_on_call",
        "description": "Check if user was on an approved on-call shift covering the timestamp and system.",
        "parameters": WasOnCallArgs.model_json_schema(),
    },
    {
        "name": "leave_overlap",
        "description": "Check if user was on approved leave during the access timestamp.",
        "parameters": LeaveOverlapArgs.model_json_schema(),
    },
    {
        "name": "change_ticket_covering",
        "description": "Check if an approved change management ticket covered the user, system, and time window.",
        "parameters": ChangeTicketCoveringArgs.model_json_schema(),
    },
    {
        "name": "project_membership",
        "description": "Check if user is an authorized member of a cross-functional project authorizing access.",
        "parameters": ProjectMembershipArgs.model_json_schema(),
    },
    {
        "name": "recent_role_change",
        "description": "Check if user underwent a departmental transfer or promotion within window_days.",
        "parameters": RecentRoleChangeArgs.model_json_schema(),
    },
    {
        "name": "approved_exception",
        "description": "Check if a formal security exception covers the user's privileged entitlement.",
        "parameters": ApprovedExceptionArgs.model_json_schema(),
    },
    {
        "name": "peer_comparison",
        "description": "Compare user's feature value against their organizational peer group distribution.",
        "parameters": PeerComparisonArgs.model_json_schema(),
    },
    {
        "name": "own_history_baseline",
        "description": "Compare user's feature value against their own historical 30-day baseline.",
        "parameters": OwnHistoryBaselineArgs.model_json_schema(),
    },
    {
        "name": "is_privileged_by_title",
        "description": "Evaluate if user's job role standardly requires administrative privileges.",
        "parameters": IsPrivilegedByTitleArgs.model_json_schema(),
    },
    {
        "name": "service_account_owner",
        "description": "Retrieve custodian information for service account or flag orphan.",
        "parameters": ServiceAccountOwnerArgs.model_json_schema(),
    },
]

# ── Tool Implementations ──────────────────────────────────────────────────────


def _match_user(target: str, record_user: str) -> bool:
    t = str(target).strip().lower()
    r = str(record_user).strip().lower()
    if t == r:
        return True
    if "@" in t and "@" in r and t.split("@")[0] == r.split("@")[0]:
        return True
    return False


def _match_system(target: str | None, record_system: str | None) -> bool:
    if not target or not record_system:
        return True
    t = str(target).strip().lower()
    r = str(record_system).strip().lower()
    return t == r or t in r or r in t


def was_on_call(bundle: CanonicalBundle, user: str, ts: str, system: str | None = None) -> tuple[bool, list[dict], str]:
    target_dt = parse_iso_dt(ts)
    if not target_dt:
        return False, [], f"Invalid timestamp format '{ts}'"

    evidence = []
    for shift in bundle.org_context.oncall:
        if _match_user(user, shift.get("user", "")) and _match_system(system, shift.get("system")):
            s_dt = parse_iso_dt(shift.get("start_time"))
            e_dt = parse_iso_dt(shift.get("end_time"))
            if s_dt and e_dt and s_dt <= target_dt <= e_dt:
                evidence.append(shift)

    if evidence:
        return True, evidence, f"User '{user}' was scheduled on-call during {ts}"
    return False, [], f"No active on-call shift found for '{user}' at {ts}"


def leave_overlap(bundle: CanonicalBundle, user: str, ts: str) -> tuple[bool, list[dict], str]:
    target_dt = parse_iso_dt(ts)
    if not target_dt:
        return False, [], f"Invalid timestamp format '{ts}'"

    evidence = []
    for rec in bundle.org_context.leave:
        if _match_user(user, rec.get("user", "")):
            s_dt = parse_iso_dt(rec.get("start_date"))
            e_dt = parse_iso_dt(rec.get("end_date"))
            if s_dt and e_dt and s_dt <= target_dt <= e_dt:
                evidence.append(rec)

    if evidence:
        return True, evidence, f"User '{user}' was on approved leave during {ts}"
    return False, [], f"User '{user}' was not on leave during {ts}"


def change_ticket_covering(bundle: CanonicalBundle, user: str, system: str, ts: str) -> tuple[bool, list[dict], str]:
    target_dt = parse_iso_dt(ts)
    if not target_dt:
        return False, [], f"Invalid timestamp format '{ts}'"

    evidence = []
    for t in bundle.org_context.tickets:
        status = str(t.get("status", "")).upper()
        if status != "APPROVED":
            continue

        if _match_user(user, t.get("user", "")) and _match_system(system, t.get("system", "")):
            s_dt = parse_iso_dt(t.get("start_time"))
            e_dt = parse_iso_dt(t.get("end_time"))
            if s_dt and e_dt and s_dt <= target_dt <= e_dt:
                evidence.append(t)

    if evidence:
        t_id = evidence[0].get("ticket_id", "CHG")
        return True, evidence, f"Access covered by approved change ticket {t_id} for {system}"
    return False, [], f"No approved change ticket found covering '{user}' on system '{system}' at {ts}"


def project_membership(bundle: CanonicalBundle, user: str, system: str, ts: str | None = None) -> tuple[bool, list[dict], str]:
    target_dt = parse_iso_dt(ts) if ts else None

    evidence = []
    for prj in bundle.org_context.projects:
        if _match_user(user, prj.get("user", "")) and _match_system(system, prj.get("system", "")):
            if target_dt:
                s_dt = parse_iso_dt(prj.get("start_date"))
                e_dt = parse_iso_dt(prj.get("end_date"))
                if s_dt and e_dt and not (s_dt <= target_dt <= e_dt):
                    continue
            evidence.append(prj)

    if evidence:
        p_id = evidence[0].get("project_id", "PRJ")
        return True, evidence, f"User is authorized member of project {p_id} ({system})"
    return False, [], f"No project membership authorizing '{user}' on system '{system}'"


def recent_role_change(bundle: CanonicalBundle, user: str, ts: str, window_days: int = 60) -> tuple[bool, list[dict], str]:
    target_dt = parse_iso_dt(ts)
    if not target_dt:
        return False, [], f"Invalid timestamp format '{ts}'"

    evidence = []
    cutoff = target_dt - timedelta(days=window_days)

    for h in bundle.org_context.hr_events:
        if _match_user(user, h.get("user", "")):
            if str(h.get("event_type", "")).upper() in ("TERMINATION", "RESIGNATION", "SEPARATION"):
                continue  # leaving the company is not a role change that explains new access
            eff_dt = parse_iso_dt(h.get("effective_date"))
            if eff_dt and cutoff <= eff_dt <= target_dt:
                evidence.append(h)

    if evidence:
        ev_type = evidence[0].get("event_type", "transfer")
        return True, evidence, f"User underwent recent {ev_type} on {evidence[0].get('effective_date')}"
    return False, [], f"No role changes recorded for '{user}' within {window_days} days of {ts}"


def approved_exception(bundle: CanonicalBundle, user: str, entitlement: str, ts: str | None = None) -> tuple[bool, list[dict], str]:
    target_dt = parse_iso_dt(ts) if ts else datetime.now(UTC)

    evidence = []
    ent_norm = entitlement.strip().lower()
    ident = next((i for i in bundle.identities if i.identity_id == user or i.email == user), None)
    held = {e.system.lower() for e in bundle.entitlements if ident and e.extra.get("identity_id") == ident.identity_id}

    for exc in bundle.org_context.exceptions:
        if _match_user(user, exc.get("user", "")):
            rec_ent = str(exc.get("entitlement", "")).strip().lower()
            if ent_norm in rec_ent or rec_ent in ent_norm or rec_ent in held:
                exp_dt = parse_iso_dt(exc.get("expiry_date"))
                if not exp_dt or (target_dt and exp_dt >= target_dt):
                    evidence.append(exc)

    if evidence:
        e_id = evidence[0].get("exception_id", "EXC")
        return True, evidence, f"Approved security exemption {e_id} covers entitlement '{entitlement}'"
    return False, [], f"No approved security exception for '{user}' and entitlement '{entitlement}'"


def _feature_value(events: list, feature: str) -> float | None:
    """Computes a behavioural feature from raw events; None when the feature is unknown."""
    if not events:
        return 0.0
    if feature == "event_count":
        return float(len(events))
    if feature == "distinct_systems":
        return float(len({e.system for e in events if e.system}))
    if feature == "failure_rate":
        return sum(1 for e in events if not e.success) / len(events)
    if feature == "after_hours_ratio":
        off = 0
        for e in events:
            dt = parse_iso_dt(e.timestamp)
            if dt and (dt.hour < 8 or dt.hour >= 18 or dt.weekday() >= 5):
                off += 1
        return off / len(events)
    return None


_FEATURES = "event_count, distinct_systems, failure_rate, after_hours_ratio"


def peer_comparison(bundle: CanonicalBundle, user: str, feature: str) -> tuple[bool, list[dict], str]:
    """True only when the user's value sits within 1.5 standard deviations of department peers."""
    ident = next((i for i in bundle.identities if i.identity_id == user or i.email == user), None)
    if not ident:
        return False, [], f"User '{user}' not found; cannot build a peer group"
    dept = ident.department or "general"
    by_user: dict[str, list] = {}
    for e in bundle.events:
        by_user.setdefault(e.user_key, []).append(e)
    peers = [i.identity_id for i in bundle.identities if i.department == ident.department and i.identity_id != ident.identity_id]
    peer_vals = [v for p in peers if (v := _feature_value(by_user.get(p, []), feature)) is not None]
    user_val = _feature_value(by_user.get(ident.identity_id, []), feature)
    if user_val is None:
        return False, [], f"Unknown feature '{feature}'; supported: {_FEATURES}"
    if len(peer_vals) < 5:
        return False, [], f"Too few peers in department '{dept}' to compare '{feature}'"
    mean = sum(peer_vals) / len(peer_vals)
    std = (sum((v - mean) ** 2 for v in peer_vals) / len(peer_vals)) ** 0.5
    z = 0.0 if std == 0 and user_val == mean else (user_val - mean) / (std or 1e-9)
    evidence = [{"department": dept, "peer_count": len(peer_vals), "peer_mean": round(mean, 3),
                 "user_value": round(user_val, 3), "deviation_z": round(z, 2)}]
    if abs(z) <= 1.5:
        return True, evidence, f"User '{feature}' ({user_val:.2f}) is within peer range in '{dept}' (z={z:.1f})"
    return False, evidence, f"User '{feature}' ({user_val:.2f}) deviates from '{dept}' peers (z={z:.1f})"


def own_history_baseline(bundle: CanonicalBundle, user: str, feature: str) -> tuple[bool, list[dict], str]:
    """True only when the last 30 days match the user's own earlier baseline (>=10 prior events)."""
    u_events = [e for e in bundle.get_events_for_user(user) if parse_iso_dt(e.timestamp)]
    if not u_events:
        return False, [], f"No telemetry for user '{user}'"
    cutoff = max(parse_iso_dt(e.timestamp) for e in u_events) - timedelta(days=30)
    prior = [e for e in u_events if parse_iso_dt(e.timestamp) < cutoff]
    recent = [e for e in u_events if parse_iso_dt(e.timestamp) >= cutoff]
    if len(prior) < 10:
        return False, [], f"No established baseline: only {len(prior)} events before the last 30 days"
    base, now = _feature_value(prior, feature), _feature_value(recent, feature)
    if base is None:
        return False, [], f"Unknown feature '{feature}'; supported: {_FEATURES}"
    evidence = [{"user": user, "baseline_events": len(prior), "baseline": round(base, 3), "last_30d": round(now, 3)}]
    if now <= base * 1.5 + 0.05:
        return True, evidence, f"Last-30-day '{feature}' ({now:.2f}) matches the user's own baseline ({base:.2f})"
    return False, evidence, f"Last-30-day '{feature}' ({now:.2f}) is well above the user's own baseline ({base:.2f})"


def is_privileged_by_title(job_title: str) -> tuple[bool, list[dict], str]:
    jt = str(job_title).lower()
    priv_roles = ("admin", "devops", "sre", "cloud engineer", "architect", "dba", "security", "lead")
    is_priv = any(r in jt for r in priv_roles)

    if is_priv:
        return True, [{"job_title": job_title, "matches": [r for r in priv_roles if r in jt]}], f"Role '{job_title}' standardly requires administrative system access"
    return False, [], f"Role '{job_title}' standardly does not require administrative privileges"


def service_account_owner(bundle: CanonicalBundle, account: str) -> tuple[bool, list[dict], str]:
    target_acc = next((a for a in bundle.accounts if a.account_id == account or a.username == account), None)
    if not target_acc:
        return False, [], f"Account '{account}' not found in bundle"

    ident_id = target_acc.extra.get("identity_id") or target_acc.employee_id_hint
    if ident_id:
        owner = next((i for i in bundle.identities if i.identity_id == ident_id), None)
        if owner:
            evidence = [{"account": account, "owner_id": owner.identity_id, "owner_name": owner.full_name, "owner_email": owner.email}]
            return True, evidence, f"Service account '{account}' is managed by custodian {owner.full_name}"

    return False, [], f"Service account '{account}' has no recorded human owner/custodian"


# ── Tool Dispatcher with Strict Argument Schema Validation ────────────────────


def execute_tool(
    bundle: CanonicalBundle,
    tool_name: str,
    args: dict[str, Any],
    tool_call_id: str | None = None,
) -> dict[str, Any]:
    """Execute a verification tool with strict Pydantic argument validation."""
    cid = tool_call_id or f"call_{uuid.uuid4().hex[:8]}"

    if tool_name not in TOOL_SCHEMAS:
        return {
            "tool_call_id": cid,
            "tool": tool_name,
            "result": False,
            "evidence_rows": [],
            "message": f"Tool '{tool_name}' is not in the allowed tool registry.",
            "error": "DisallowedTool",
        }

    schema_cls = TOOL_SCHEMAS[tool_name]
    try:
        validated_args = schema_cls.model_validate(args).model_dump()
    except ValidationError as err:
        return {
            "tool_call_id": cid,
            "tool": tool_name,
            "result": False,
            "evidence_rows": [],
            "message": f"Argument schema validation failed for tool '{tool_name}': {err.errors()}",
            "error": "InvalidArguments",
        }

    try:
        if tool_name == "was_on_call":
            res, ev, msg = was_on_call(bundle, validated_args["user"], validated_args["ts"], validated_args.get("system"))
        elif tool_name == "leave_overlap":
            res, ev, msg = leave_overlap(bundle, validated_args["user"], validated_args["ts"])
        elif tool_name == "change_ticket_covering":
            res, ev, msg = change_ticket_covering(bundle, validated_args["user"], validated_args["system"], validated_args["ts"])
        elif tool_name == "project_membership":
            res, ev, msg = project_membership(bundle, validated_args["user"], validated_args["system"], validated_args.get("ts"))
        elif tool_name == "recent_role_change":
            res, ev, msg = recent_role_change(bundle, validated_args["user"], validated_args["ts"], validated_args.get("window_days", 60))
        elif tool_name == "approved_exception":
            res, ev, msg = approved_exception(bundle, validated_args["user"], validated_args["entitlement"], validated_args.get("ts"))
        elif tool_name == "peer_comparison":
            res, ev, msg = peer_comparison(bundle, validated_args["user"], validated_args["feature"])
        elif tool_name == "own_history_baseline":
            res, ev, msg = own_history_baseline(bundle, validated_args["user"], validated_args["feature"])
        elif tool_name == "is_privileged_by_title":
            res, ev, msg = is_privileged_by_title(validated_args["job_title"])
        elif tool_name == "service_account_owner":
            res, ev, msg = service_account_owner(bundle, validated_args["account"])
        else:
            res, ev, msg = False, [], "Unknown tool"

        return {
            "tool_call_id": cid,
            "tool": tool_name,
            "result": res,
            "evidence_rows": ev,
            "message": msg,
        }
    except Exception as e:
        return {
            "tool_call_id": cid,
            "tool": tool_name,
            "result": False,
            "evidence_rows": [],
            "message": f"Tool execution failed: {e}",
            "error": "ExecutionError",
        }
