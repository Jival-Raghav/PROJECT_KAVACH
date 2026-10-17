"""
backend/security/invariance.py — Verdict Invariance Verification.

Validates that untrusted input fields (job titles, descriptions) cannot manipulate
security verdicts or artificially downgrade severity ratings.
"""
from __future__ import annotations

from typing import Any

SEVERITY_RANKS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def verify_verdict_invariance(
    adjudication_baseline: dict[str, Any],
    adjudication_defended: dict[str, Any],
) -> dict[str, Any]:
    """
    Compares adjudication verdicts. If the presence of untrusted text lowered the severity,
    flags manipulation and enforces the stricter baseline severity.
    """
    base_sev = adjudication_baseline.get("severity", "MEDIUM").upper()
    def_sev = adjudication_defended.get("severity", "MEDIUM").upper()

    base_rank = SEVERITY_RANKS.get(base_sev, 2)
    def_rank = SEVERITY_RANKS.get(def_sev, 2)

    manipulation_detected = False
    enforced_severity = def_sev

    # If defended rank is lower than baseline rank, potential prompt injection manipulation occurred
    if def_rank < base_rank:
        manipulation_detected = True
        enforced_severity = base_sev  # Enforce the higher severity floor

    return {
        "manipulation_detected": manipulation_detected,
        "baseline_severity": base_sev,
        "evaluated_severity": def_sev,
        "enforced_severity": enforced_severity,
        "status": "TAMPER_PREVENTED" if manipulation_detected else "VERIFIED_INVARIANT",
    }
