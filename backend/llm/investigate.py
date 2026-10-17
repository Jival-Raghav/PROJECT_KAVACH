"""backend/llm/investigate.py
Full Three-Pass Investigation Orchestrator for Phase 4 Devil's Advocate Co-Pilot.

Pipeline:
1. Pass 1: Prosecutor agent formulates claims from canonical profile & telemetry findings.
2. Pass 2: Devil's Advocate conducts bounded tool loop against organizational context,
   enforces citation integrity in Python code, and computes deterministic doubt_score.
3. Pass 3: CISO Adjudicator synthesizes binding verdict, timeline, and concrete remediation.
"""
from __future__ import annotations

import logging
from typing import Any

from core.models import CanonicalBundle
from detect.models import run_detection
from llm.adjudicator import AdjudicationVerdict, run_adjudicator
from llm.devils_advocate import run_devils_advocate
from llm.prosecutor import run_prosecutor

logger = logging.getLogger(__name__)

# In-memory investigation case dossier cache
_CASE_DOSSIER_CACHE: dict[str, AdjudicationVerdict] = {}


def investigate_user(
    bundle: CanonicalBundle,
    user_id: str,
    use_llm: bool = True,
    profile_override: dict[str, Any] | None = None,
) -> AdjudicationVerdict:
    """Run full 3-pass investigative adversarial review for an accused user."""
    # 1. Retrieve or build user detection profile
    profile = profile_override
    if not profile:
        det_result = run_detection(bundle)
        matched = [p for p in det_result.user_profiles if p["user_id"] == user_id]
        if matched:
            profile = matched[0]
        else:
            # Fallback bare profile
            ident = next((i for i in bundle.identities if i.identity_id == user_id), None)
            profile = {
                "user_id": user_id,
                "full_name": ident.full_name if ident else user_id,
                "department": ident.department if ident else "Unknown",
                "job_title": ident.job_title if ident else "Staff",
                "privilege_level": "user",
                "risk_score": 50.0,
                "severity": "REVIEW",
                "findings": [],
                "flags": [],
            }

    findings = profile.get("findings", [])
    events = bundle.get_events_for_user(user_id)

    # 2. Pass 1: Prosecutor Claims
    claims = run_prosecutor(
        bundle=bundle,
        profile=profile,
        findings=findings,
        events=events,
        use_llm=use_llm,
    )

    # 3. Pass 2: Devil's Advocate Bounded Tool Loop & Verification
    da_result = run_devils_advocate(
        bundle=bundle,
        profile=profile,
        claims=claims,
        events=events,
        use_llm=use_llm,
    )

    # 4. Pass 3: CISO Adjudication & Remediation Synthesis
    verdict = run_adjudicator(
        bundle=bundle,
        profile=profile,
        claims=claims,
        da_result=da_result,
        use_llm=use_llm,
    )

    _CASE_DOSSIER_CACHE[user_id] = verdict
    return verdict


def get_case_dossier(user_id: str) -> AdjudicationVerdict | None:
    """Retrieve existing case dossier for a user."""
    return _CASE_DOSSIER_CACHE.get(user_id)


def list_investigated_cases() -> list[dict[str, Any]]:
    """List summary records of all investigated cases."""
    return [
        {
            "user_id": v.user_id,
            "verdict": v.verdict,
            "severity": v.severity,
            "doubt_score": v.doubt_score,
            "summary": v.summary,
            "remediation_count": len(v.remediation_steps),
        }
        for v in _CASE_DOSSIER_CACHE.values()
    ]
