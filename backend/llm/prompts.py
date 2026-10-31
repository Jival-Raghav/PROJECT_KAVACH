"""
llm/prompts.py
Two-pass Devil's Advocate prompt templates.

Pass 1 — PROSECUTOR: Build the case against the user with specific evidence.
Pass 2 — DEVIL'S ADVOCATE: Challenge the prosecution with contextual mitigators.

Both prompts demand JSON output so responses are machine-parseable.
"""
from __future__ import annotations

from typing import Any


SYSTEM_PROSECUTOR = """You are a senior cybersecurity analyst at a large enterprise.
Your job is to PROSECUTE suspicious identity and access patterns.
Be specific: cite exact timestamps, resource names, and counts from the evidence.
Write as if presenting to the CISO. Be factual, not alarmist.
You MUST respond with valid JSON only — no markdown, no explanation outside the JSON."""

SYSTEM_DEVILS_ADVOCATE = """You are a seasoned security architect acting as DEFENSE COUNSEL
reviewing a security finding before it reaches the CISO.
Your job: find every legitimate explanation that could explain the flagged behaviour.
Consider: role requirements, new hires, on-call rotations, month-end/quarter-end
business cycles, contractor patterns, automated service accounts, sabbaticals.
You MUST respond with valid JSON only — no markdown, no explanation outside the JSON.
A doubt_score of 0.0 means you are certain it is a real threat.
A doubt_score of 1.0 means it is almost certainly a false positive."""


def build_prosecutor_messages(
    profile: dict[str, Any],
    flagged_events: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Builds the message list for the Prosecutor LLM call."""
    # Summarise flagged events concisely to stay within token budget
    event_summary = _summarise_events(flagged_events)

    user_block = f"""
USER PROFILE:
  user_id:        {profile.get('user_id')}
  username:       {profile.get('username')}
  department:     {profile.get('department')}
  job_title:      {profile.get('job_title')}
  privilege_level:{profile.get('privilege_level')}
  systems_access: {', '.join(profile.get('systems_access') or [])}
  last_login:     {profile.get('last_login')}
  days_inactive:  {profile.get('days_inactive')}
  is_active:      {profile.get('is_active')}
  hire_date:      {profile.get('hire_date')}
  is_new_hire:    {profile.get('is_new_hire')}
  risk_score:     {profile.get('risk_score')}
  flags:          {', '.join(profile.get('flags') or []) or 'none'}
  after_hours_ratio:      {profile.get('after_hours_ratio', 0.0):.1%}
  high_sensitivity_ratio: {profile.get('high_sensitivity_ratio', 0.0):.1%}
  fail_ratio:             {profile.get('fail_ratio', 0.0):.1%}
  export_count:           {profile.get('export_count', 0)}
  admin_op_count:         {profile.get('admin_op_count', 0)}
  sod_violations:         {len(profile.get('sod_violations') or [])}
  compliance_gaps:        {len(profile.get('compliance_gaps') or [])}

FLAGGED EVENTS ({len(flagged_events)} total, showing up to 15):
{event_summary}
""".strip()

    return [
        {"role": "system", "content": SYSTEM_PROSECUTOR},
        {
            "role": "user",
            "content": (
                f"Analyse the following identity access data and write a prosecution.\n\n"
                f"{user_block}\n\n"
                "Respond with JSON in exactly this schema:\n"
                "{\n"
                '  "prosecution": "<200-400 word narrative citing specific evidence>",\n'
                '  "severity": "<CRITICAL|HIGH|REVIEW|INFORMATIONAL>",\n'
                '  "key_evidence": ["<evidence item 1>", "<evidence item 2>", ...],\n'
                '  "breach_impact": "<what systems/data are at risk if this account is compromised>"\n'
                "}"
            ),
        },
    ]


def build_devils_advocate_messages(
    profile: dict[str, Any],
    flagged_events: list[dict[str, Any]],
    prosecution_result: dict[str, Any],
) -> list[dict[str, str]]:
    """Builds the message list for the Devil's Advocate LLM call."""
    context = f"""
ACCUSED USER:
  user_id:     {profile.get('user_id')}
  username:    {profile.get('username')}
  department:  {profile.get('department')}
  job_title:   {profile.get('job_title')}
  privilege:   {profile.get('privilege_level')}
  hire_date:   {profile.get('hire_date')}
  is_new_hire: {profile.get('is_new_hire')}
  days_inactive: {profile.get('days_inactive')}
  is_active:   {profile.get('is_active')}

PROSECUTION FINDING:
  severity:   {prosecution_result.get('severity')}
  narrative:  {prosecution_result.get('prosecution', '')[:600]}
  evidence:   {'; '.join(prosecution_result.get('key_evidence', [])[:5])}
""".strip()

    return [
        {"role": "system", "content": SYSTEM_DEVILS_ADVOCATE},
        {
            "role": "user",
            "content": (
                f"Review this security finding and challenge it as defence counsel.\n\n"
                f"{context}\n\n"
                "Respond with JSON in exactly this schema:\n"
                "{\n"
                '  "challenge": "<150-300 word defence narrative with legitimate explanations>",\n'
                '  "doubt_score": <float 0.0 to 1.0>,\n'
                '  "mitigating_factors": ["<factor 1>", "<factor 2>", ...],\n'
                '  "final_recommendation": "<specific, actionable next step for the analyst>"\n'
                "}"
            ),
        },
    ]


# ─── Severity Gate ────────────────────────────────────────────────────────────

SEVERITY_DOWNGRADE: dict[str, str] = {
    "CRITICAL": "HIGH",
    "HIGH": "REVIEW",
    "REVIEW": "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
}


def apply_doubt_gate(prosecution_severity: str, doubt_score: float) -> str:
    """
    If doubt_score > 0.65, downgrade severity by one tier.
    If doubt_score > 0.85, downgrade again (two tiers total).
    This is the DA gate that prevents false positives from reaching analysts.
    """
    severity = prosecution_severity.upper()
    if doubt_score > 0.85:
        severity = SEVERITY_DOWNGRADE.get(severity, severity)
        severity = SEVERITY_DOWNGRADE.get(severity, severity)
    elif doubt_score > 0.65:
        severity = SEVERITY_DOWNGRADE.get(severity, severity)
    return severity


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _summarise_events(events: list[dict[str, Any]], limit: int = 15) -> str:
    lines = []
    for ev in events[:limit]:
        lines.append(
            f"  [{ev.get('timestamp','?')}] {ev.get('action','?')} "
            f"→ {ev.get('resource','?')} "
            f"(sensitivity={ev.get('resource_sensitivity','?')}, "
            f"status={ev.get('status','?')}, "
            f"time_class={ev.get('time_classification','?')})"
        )
    if len(events) > limit:
        lines.append(f"  ... and {len(events) - limit} more events")
    return "\n".join(lines) if lines else "  No flagged events."
