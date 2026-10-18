"""backend/llm/devils_advocate.py
Pass 2: Evidence-Grounded Devil's Advocate Agent for Kavach v2.

Features:
- Bounded tool execution loop (max 6 calls per case).
- Strict Pydantic argument validation via llm/tools.py.
- Code-level Citation Enforcement: Any refuted/weakened claim without verified
  tool evidence rows is automatically downgraded to 'unverifiable'.
- Hard-rule claims (SoD, Leaver-Active, Stale Privileged) are forced to 'stands'.
- Deterministic doubt_score calculation: Σ(w_i · v_i) / Σ w_i.
- Bounded severity adjustment (maximum 1 level drop normally; 2 levels only if all non-hard refuted; never below REVIEW if hard rule present).
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from config import get_settings
from core.models import CanonicalBundle, CanonicalEvent
from llm.client import get_da_client
from llm.jsonutil import parse_llm_json
from llm.prompts import build_da_tool_loop_messages
from llm.prosecutor import ProsecutorClaim
from llm.tools import TOOL_METADATA, execute_tool
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}

STATUS_VALUES = {
    "refuted": 1.0,
    "weakened": 0.5,
    "stands": 0.0,
    "unverifiable": 0.0,
}

SEVERITY_TIERS = ["INFORMATIONAL", "REVIEW", "HIGH", "CRITICAL"]


class ClaimRebuttal(BaseModel):
    claim_id: str
    status: str  # refuted | weakened | stands | unverifiable
    cited_tool_call_ids: list[str] = Field(default_factory=list)
    rationale: str
    original_severity: str = "medium"
    hard_rule: bool = False


class DAResult(BaseModel):
    rebuttals: list[ClaimRebuttal]
    doubt_score: float
    original_severity: str
    adjusted_severity: str
    tool_results: list[dict[str, Any]]
    iterations_run: int


def calculate_doubt_score(claims: list[ProsecutorClaim], rebuttals: list[ClaimRebuttal]) -> float:
    """Deterministically computes doubt_score = Σ(sev_weight_i · status_value_i) / Σ sev_weight_i."""
    reb_map = {r.claim_id: r for r in rebuttals}

    total_weight = 0.0
    accumulated_value = 0.0

    for c in claims:
        w = SEVERITY_WEIGHTS.get(c.severity.lower(), 2.0)
        total_weight += w

        r = reb_map.get(c.claim_id)
        if r:
            v = STATUS_VALUES.get(r.status.lower(), 0.0)
            accumulated_value += w * v

    if total_weight <= 0.0:
        return 0.0
    return round(accumulated_value / total_weight, 4)


def compute_adjusted_severity(
    original_severity: str,
    claims: list[ProsecutorClaim],
    rebuttals: list[ClaimRebuttal],
    doubt_score: float,
) -> str:
    """Calculates adjusted severity with strict safety bounds.

    - Lowers by at most 1 level normally.
    - Lowers by 2 levels only if all non-hard claims are refuted with citations (doubt_score >= 0.95).
    - NEVER drops below REVIEW if any hard rule claim exists.
    """
    orig = original_severity.upper()
    if orig not in SEVERITY_TIERS:
        orig = "REVIEW"

    current_idx = SEVERITY_TIERS.index(orig)
    has_hard_rule = any(c.hard_rule for c in claims)

    # If doubt score is low (< 0.40), severity stands unchanged
    if doubt_score < 0.40:
        return orig

    # Determine allowable reduction
    drop = 1
    if doubt_score >= 0.95 and all(r.status == "refuted" for r in rebuttals if not r.hard_rule):
        drop = 2

    new_idx = max(0, current_idx - drop)

    # Floor at REVIEW if any hard rule violation exists
    if has_hard_rule:
        review_idx = SEVERITY_TIERS.index("REVIEW")
        new_idx = max(new_idx, review_idx)

    return SEVERITY_TIERS[new_idx]


def enforce_citations(
    claims: list[ProsecutorClaim],
    rebuttals: list[ClaimRebuttal],
    tool_results: list[dict[str, Any]],
) -> list[ClaimRebuttal]:
    """Enforces citation integrity in Python code:

    1. Any claim marked 'refuted' or 'weakened' must cite at least one executed tool call whose result is True.
       Otherwise it is downgraded to 'unverifiable'.
    2. Any claim with hard_rule=True is strictly forced to 'stands'.
    """
    valid_tool_cids = {r["tool_call_id"]: r for r in tool_results if r.get("result") is True}
    claim_map = {c.claim_id: c for c in claims}

    verified_rebuttals: list[ClaimRebuttal] = []

    for reb in rebuttals:
        c = claim_map.get(reb.claim_id)
        is_hard = c.hard_rule if c else reb.hard_rule

        # Rule 1: Hard rules cannot be refuted
        if is_hard:
            verified_rebuttals.append(
                ClaimRebuttal(
                    claim_id=reb.claim_id,
                    status="stands",
                    cited_tool_call_ids=[],
                    rationale=f"Hard security rule cannot be dismissed: {reb.rationale}",
                    original_severity=c.severity if c else reb.original_severity,
                    hard_rule=True,
                )
            )
            continue

        # Rule 2: Citation verification
        if reb.status in ("refuted", "weakened"):
            supported = any(cid in valid_tool_cids for cid in reb.cited_tool_call_ids)
            if not supported:
                verified_rebuttals.append(
                    ClaimRebuttal(
                        claim_id=reb.claim_id,
                        status="unverifiable",
                        cited_tool_call_ids=[],
                        rationale=f"Downgraded to unverifiable: cited tools do not contain supporting evidence rows. Original: {reb.rationale}",
                        original_severity=c.severity if c else reb.original_severity,
                        hard_rule=False,
                    )
                )
                continue

        verified_rebuttals.append(
            ClaimRebuttal(
                claim_id=reb.claim_id,
                status=reb.status,
                cited_tool_call_ids=reb.cited_tool_call_ids,
                rationale=reb.rationale,
                original_severity=c.severity if c else reb.original_severity,
                hard_rule=False,
            )
        )

    return verified_rebuttals


def run_deterministic_da(
    bundle: CanonicalBundle,
    profile: dict[str, Any],
    claims: list[ProsecutorClaim],
    events: list[CanonicalEvent],
) -> DAResult:
    """Fallback deterministic Devil's Advocate querying evidence tools directly."""
    tool_results: list[dict[str, Any]] = []
    rebuttals: list[ClaimRebuttal] = []

    u_id = str(profile.get("user_id", ""))
    earliest_event_ts = events[0].timestamp if events and events[0].timestamp else "2026-03-25T12:00:00Z"
    target_system = events[0].system if events and events[0].system else "PROD_DB"

    for c in claims:
        if c.hard_rule:
            rebuttals.append(
                ClaimRebuttal(
                    claim_id=c.claim_id,
                    status="stands",
                    cited_tool_call_ids=[],
                    rationale="Deterministic compliance/SoD hard rule cannot be dismissed.",
                    original_severity=c.severity,
                    hard_rule=True,
                )
            )
            continue

        refuted = False
        cited_cids: list[str] = []

        # Tool 1: Check On-Call schedule
        if c.type in ("after_hours", "sensitive_access", "geo_anomaly"):
            cid = f"call_{uuid.uuid4().hex[:6]}"
            res = execute_tool(
                bundle,
                "was_on_call",
                {"user": u_id, "ts": earliest_event_ts, "system": target_system},
                tool_call_id=cid,
            )
            tool_results.append(res)
            if res.get("result"):
                refuted = True
                cited_cids.append(cid)
                rebuttals.append(
                    ClaimRebuttal(
                        claim_id=c.claim_id,
                        status="refuted",
                        cited_tool_call_ids=cited_cids,
                        rationale=res.get("message", "Covered by on-call schedule"),
                        original_severity=c.severity,
                        hard_rule=False,
                    )
                )
                continue

        # Tool 2: Check Change Ticket
        if c.type in ("sensitive_access", "mass_access", "after_hours"):
            cid = f"call_{uuid.uuid4().hex[:6]}"
            res = execute_tool(
                bundle,
                "change_ticket_covering",
                {"user": u_id, "system": target_system, "ts": earliest_event_ts},
                tool_call_id=cid,
            )
            tool_results.append(res)
            if res.get("result"):
                refuted = True
                cited_cids.append(cid)
                rebuttals.append(
                    ClaimRebuttal(
                        claim_id=c.claim_id,
                        status="refuted",
                        cited_tool_call_ids=cited_cids,
                        rationale=res.get("message", "Covered by approved change ticket"),
                        original_severity=c.severity,
                        hard_rule=False,
                    )
                )
                continue

        # Tool 3: Check Project Membership
        if c.type in ("privilege_creep", "peer_outlier", "sensitive_access"):
            cid = f"call_{uuid.uuid4().hex[:6]}"
            res = execute_tool(
                bundle,
                "project_membership",
                {"user": u_id, "system": target_system, "ts": earliest_event_ts},
                tool_call_id=cid,
            )
            tool_results.append(res)
            if res.get("result"):
                refuted = True
                cited_cids.append(cid)
                rebuttals.append(
                    ClaimRebuttal(
                        claim_id=c.claim_id,
                        status="refuted",
                        cited_tool_call_ids=cited_cids,
                        rationale=res.get("message", "Authorized by cross-functional project membership"),
                        original_severity=c.severity,
                        hard_rule=False,
                    )
                )
                continue

        # Tool 4: Check Recent Role Change
        if c.type in ("privilege_creep", "peer_outlier", "distinct_systems"):
            cid = f"call_{uuid.uuid4().hex[:6]}"
            res = execute_tool(
                bundle,
                "recent_role_change",
                {"user": u_id, "ts": earliest_event_ts, "window_days": 60},
                tool_call_id=cid,
            )
            tool_results.append(res)
            if res.get("result"):
                refuted = True
                cited_cids.append(cid)
                rebuttals.append(
                    ClaimRebuttal(
                        claim_id=c.claim_id,
                        status="refuted",
                        cited_tool_call_ids=cited_cids,
                        rationale=res.get("message", "Authorized due to recent organizational role transfer"),
                        original_severity=c.severity,
                        hard_rule=False,
                    )
                )
                continue

        # Tool 5: Check Security Exception
        if c.type in ("stale_privileged", "sensitive_access"):
            cid = f"call_{uuid.uuid4().hex[:6]}"
            res = execute_tool(
                bundle,
                "approved_exception",
                {"user": u_id, "entitlement": target_system, "ts": earliest_event_ts},
                tool_call_id=cid,
            )
            tool_results.append(res)
            if res.get("result"):
                refuted = True
                cited_cids.append(cid)
                rebuttals.append(
                    ClaimRebuttal(
                        claim_id=c.claim_id,
                        status="refuted",
                        cited_tool_call_ids=cited_cids,
                        rationale=res.get("message", "Covered by approved security exception"),
                        original_severity=c.severity,
                        hard_rule=False,
                    )
                )
                continue

        # If no tool supported refutation
        if not refuted:
            rebuttals.append(
                ClaimRebuttal(
                    claim_id=c.claim_id,
                    status="stands",
                    cited_tool_call_ids=[],
                    rationale="No mitigating evidence rows or authorizations found in organizational context.",
                    original_severity=c.severity,
                    hard_rule=False,
                )
            )

    verified = enforce_citations(claims, rebuttals, tool_results)
    doubt = calculate_doubt_score(claims, verified)
    orig_sev = str(profile.get("severity", "REVIEW")).upper()
    adj_sev = compute_adjusted_severity(orig_sev, claims, verified, doubt)

    return DAResult(
        rebuttals=verified,
        doubt_score=doubt,
        original_severity=orig_sev,
        adjusted_severity=adj_sev,
        tool_results=tool_results,
        iterations_run=len(tool_results),
    )


def run_devils_advocate(
    bundle: CanonicalBundle,
    profile: dict[str, Any],
    claims: list[ProsecutorClaim],
    events: list[CanonicalEvent],
    use_llm: bool = True,
    max_tool_iterations: int = 8,
) -> DAResult:
    """Executes Pass 2 (Devil's Advocate) iterative tool loop with citation enforcement."""
    cfg = get_settings()
    if not use_llm or cfg.LLM_REPLAY_ONLY or cfg.DA_PROVIDER.value == "none":
        return run_deterministic_da(bundle, profile, claims, events)

    try:
        client = get_da_client()
        tool_results: list[dict[str, Any]] = []
        conversation_history: list[dict[str, str]] = []

        claims_payload = [c.model_dump() for c in claims]
        timestamps = sorted(e.timestamp for e in events if e.timestamp)
        case_context = {
            "user": str(profile.get("user_id", "")),
            "first_event_ts": timestamps[0] if timestamps else None,
            "last_event_ts": timestamps[-1] if timestamps else None,
            "entitlements": sorted({e.system for e in bundle.entitlements
                                    if e.extra.get("identity_id") == str(profile.get("user_id", ""))}),
            "systems": sorted({e.system for e in events if e.system and e.resource_sensitivity == "high"})
            or sorted({e.system for e in events if e.system})[:5],
        }

        # Iterative tool calling loop (bounded at max_tool_iterations)
        for _ in range(max_tool_iterations):
            messages = build_da_tool_loop_messages(
                claims=claims_payload,
                available_tools=TOOL_METADATA,
                history=conversation_history,
                context=case_context,
            )

            parsed = parse_llm_json(client.chat(messages, temperature=0.2, max_tokens=3000))
            if parsed is None:
                break
            clean_resp = json.dumps(parsed)

            # Check if model requested a tool call
            if "tool" in parsed and "args" in parsed:
                t_name = parsed["tool"]
                t_args = parsed["args"]
                call_id = f"call_{uuid.uuid4().hex[:6]}"
                t_result = execute_tool(bundle, t_name, t_args, tool_call_id=call_id)
                tool_results.append(t_result)

                # Feed result back into conversation
                conversation_history.append({"role": "assistant", "content": clean_resp})
                conversation_history.append({
                    "role": "user",
                    "content": f"Tool Execution Result ({call_id}):\n{json.dumps(t_result, indent=2)}\nContinue analysis.",
                })
            elif "rebuttals" in parsed:
                # Final rebuttals emitted
                raw_rebs = parsed["rebuttals"]
                parsed_rebs: list[ClaimRebuttal] = []
                for r in raw_rebs:
                    parsed_rebs.append(
                        ClaimRebuttal(
                            claim_id=r.get("claim_id", ""),
                            status=r.get("status", "unverifiable").lower(),
                            cited_tool_call_ids=r.get("cited_tool_call_ids", []),
                            rationale=r.get("rationale", ""),
                        )
                    )

                verified = enforce_citations(claims, parsed_rebs, tool_results)
                doubt = calculate_doubt_score(claims, verified)
                orig_sev = str(profile.get("severity", "REVIEW")).upper()
                adj_sev = compute_adjusted_severity(orig_sev, claims, verified, doubt)

                return DAResult(
                    rebuttals=verified,
                    doubt_score=doubt,
                    original_severity=orig_sev,
                    adjusted_severity=adj_sev,
                    tool_results=tool_results,
                    iterations_run=len(tool_results),
                )
            else:
                break

    except Exception as exc:
        logger.warning("Devil's Advocate LLM loop failed, falling back to deterministic: %s", exc)

    return run_deterministic_da(bundle, profile, claims, events)
