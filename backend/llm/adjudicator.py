"""backend/llm/adjudicator.py
Pass 3: CISO Adjudication & Remediation Synthesis Agent for ISPAD v2.

Synthesizes prosecutor's claims, defense rebuttals, cited evidence rows, and doubt score
into a binding final verdict with a corroborated timeline and actionable remediation steps.
Remediation targets strictly reference existing bundle entities.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from config import get_settings
from core.models import CanonicalBundle
from llm.client import get_llm_client
from llm.devils_advocate import DAResult
from llm.prompts import build_adjudicator_messages
from llm.prosecutor import ProsecutorClaim
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TimelineEntry(BaseModel):
    timestamp: str
    description: str
    type: str = "alert"  # alert | mitigation | context


class RemediationStep(BaseModel):
    action: str  # REVOKE_ENTITLEMENT | DISABLE_ACCOUNT | UPDATE_TICKET | NO_ACTION
    target: str
    rationale: str


class AdjudicationVerdict(BaseModel):
    user_id: str
    verdict: str  # CONFIRMED_THREAT | MITIGATED_BENIGN | NEEDS_REVIEW
    severity: str  # CRITICAL | HIGH | REVIEW | INFORMATIONAL
    doubt_score: float
    summary: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    remediation_steps: list[RemediationStep] = Field(default_factory=list)
    claims: list[dict[str, Any]] = Field(default_factory=list)
    rebuttals: list[dict[str, Any]] = Field(default_factory=list)
    tool_results: list[dict[str, Any]] = Field(default_factory=list)


def run_deterministic_adjudicator(
    bundle: CanonicalBundle,
    profile: dict[str, Any],
    claims: list[ProsecutorClaim],
    da_result: DAResult,
) -> AdjudicationVerdict:
    """Fallback deterministic adjudicator producing verifiable, grounded verdicts."""
    uid = str(profile.get("user_id", ""))
    doubt = da_result.doubt_score
    has_hard_rule = any(c.hard_rule for c in claims)

    # 1. Determine final binding verdict
    if has_hard_rule:
        verdict = "CONFIRMED_THREAT"
    elif doubt >= 0.75 and all(r.status in ("refuted", "weakened") for r in da_result.rebuttals):
        verdict = "MITIGATED_BENIGN"
    elif doubt <= 0.35:
        verdict = "CONFIRMED_THREAT"
    else:
        verdict = "NEEDS_REVIEW"

    # 2. Build Corroborated Timeline
    timeline: list[TimelineEntry] = []
    u_events = bundle.get_events_for_user(uid)
    for e in u_events[:5]:
        timeline.append(
            TimelineEntry(
                timestamp=e.timestamp or "2026-03-25T12:00:00Z",
                description=f"Action '{e.action}' on resource '{e.resource}' ({e.system})",
                type="alert" if not e.success or e.resource_sensitivity in ("high", "crown") else "context",
            )
        )

    for r in da_result.tool_results:
        if r.get("result"):
            timeline.append(
                TimelineEntry(
                    timestamp="Context Window",
                    description=f"Verified via {r.get('tool')}: {r.get('message')}",
                    type="mitigation",
                )
            )

    # 3. Formulate Concrete Remediation Steps based on real bundle entities
    remediation: list[RemediationStep] = []
    user_accs = bundle.get_accounts_for_identity(uid)

    if verdict == "MITIGATED_BENIGN":
        remediation.append(
            RemediationStep(
                action="NO_ACTION",
                target="Identity Alerts",
                rationale=f"Investigation verified legitimate operational authorizations (Doubt score: {doubt*100:.0f}%). Alert suppressed.",
            )
        )
    else:
        # Check hard rules and high-risk findings for actionable steps
        for c in claims:
            if "sod" in c.type.lower() or "sod" in c.statement.lower():
                remediation.append(
                    RemediationStep(
                        action="REVOKE_ENTITLEMENT",
                        target=user_accs[0].account_id if user_accs else uid,
                        rationale=f"Separation of Duties conflict: {c.statement}",
                    )
                )
            elif "stale" in c.type.lower():
                remediation.append(
                    RemediationStep(
                        action="DISABLE_ACCOUNT",
                        target=user_accs[0].account_id if user_accs else uid,
                        rationale="NIST AC-2 compliance: Disable dormant or stale privileged account.",
                    )
                )
            elif "geo" in c.type.lower() or "travel" in c.statement.lower():
                remediation.append(
                    RemediationStep(
                        action="DISABLE_ACCOUNT",
                        target=user_accs[0].account_id if user_accs else uid,
                        rationale="Immediate credential reset and session invalidation due to impossible travel breach indicator.",
                    )
                )

        if not remediation:
            remediation.append(
                RemediationStep(
                    action="UPDATE_TICKET",
                    target="SOC Queue",
                    rationale=f"Forward user '{uid}' to Tier-2 SOC review with evidence dossier.",
                )
            )

    # 4. Construct Summary Narrative
    if verdict == "MITIGATED_BENIGN":
        summary = (
            f"Adjudication Verdict: MITIGATED BENIGN. Independent review by the Devil's Advocate "
            f"uncovered verified operational context refuting prosecution claims. "
            f"Documented authorizations (on-call schedule / change tickets) established legitimate business need. "
            f"Risk score lowered to {da_result.adjusted_severity} (Doubt Score: {doubt:.2f})."
        )
    elif verdict == "CONFIRMED_THREAT":
        summary = (
            f"Adjudication Verdict: CONFIRMED THREAT. Investigation confirmed severe security or compliance violations. "
            f"Defense counsel could not identify legitimate authorizations covering the flagged activity. "
            f"Immediate remediation required at {da_result.adjusted_severity} severity."
        )
    else:
        summary = (
            f"Adjudication Verdict: NEEDS REVIEW. Partial mitigating context was identified (Doubt Score: {doubt:.2f}), "
            f"but remaining behavioral anomalies lack definitive documentary authorization. "
            f"Analyst manual inspection required."
        )

    return AdjudicationVerdict(
        user_id=uid,
        verdict=verdict,
        severity=da_result.adjusted_severity,
        doubt_score=doubt,
        summary=summary,
        timeline=timeline,
        remediation_steps=remediation,
        claims=[c.model_dump() for c in claims],
        rebuttals=[r.model_dump() for r in da_result.rebuttals],
        tool_results=da_result.tool_results,
    )


def run_adjudicator(
    bundle: CanonicalBundle,
    profile: dict[str, Any],
    claims: list[ProsecutorClaim],
    da_result: DAResult,
    use_llm: bool = True,
) -> AdjudicationVerdict:
    """Executes Pass 3 (Adjudicator) with fallback to deterministic adjudication."""
    cfg = get_settings()
    if not use_llm or cfg.LLM_REPLAY_ONLY or cfg.ADJUDICATOR_PROVIDER.value == "none":
        return run_deterministic_adjudicator(bundle, profile, claims, da_result)

    try:
        client = get_llm_client()
        messages = build_adjudicator_messages(
            profile=profile,
            claims=[c.model_dump() for c in claims],
            rebuttals=[r.model_dump() for r in da_result.rebuttals],
            tool_results=da_result.tool_results,
            doubt_score=da_result.doubt_score,
            adjusted_severity=da_result.adjusted_severity,
        )

        response = client.chat(messages, temperature=0.2)
        clean_json = response.strip()

        if "```json" in clean_json:
            clean_json = clean_json.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_json:
            clean_json = clean_json.split("```")[1].split("```")[0].strip()

        parsed = json.loads(clean_json)

        return AdjudicationVerdict(
            user_id=str(profile.get("user_id", "")),
            verdict=parsed.get("verdict", "NEEDS_REVIEW"),
            severity=parsed.get("severity", da_result.adjusted_severity),
            doubt_score=float(parsed.get("doubt_score", da_result.doubt_score)),
            summary=parsed.get("summary", ""),
            timeline=[TimelineEntry(**t) for t in parsed.get("timeline", [])],
            remediation_steps=[RemediationStep(**r) for r in parsed.get("remediation_steps", [])],
            claims=[c.model_dump() for c in claims],
            rebuttals=[r.model_dump() for r in da_result.rebuttals],
            tool_results=da_result.tool_results,
        )
    except Exception as exc:
        logger.warning("Adjudicator LLM call failed, falling back to deterministic: %s", exc)

    return run_deterministic_adjudicator(bundle, profile, claims, da_result)
