from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

try:
    from anthropic import Anthropic
except Exception:  # pragma: no cover - optional dependency for the stub.
    Anthropic = None


load_dotenv()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLIENT = Anthropic(api_key=ANTHROPIC_API_KEY) if Anthropic and ANTHROPIC_API_KEY else None


SYSTEM_PROMPT = """
# STUB — teammate implements this.
# The real prompt will instruct the model to act as a senior security analyst,
# write a prosecution section, write a devil's advocate section, and return JSON.
""".strip()


def generate_narrative(user_profile: dict[str, Any], flagged_events: list[dict[str, Any]], feedback_context: dict[str, Any]) -> dict[str, Any]:
    """Returns a stub narrative payload with the exact shape the UI and API expect."""
    return {
        "prosecution": f"{user_profile['username']} has accessed high-sensitivity resources outside business hours with admin privileges.",
        "devils_advocate": f"User is in {user_profile['department']} department. Elevated access may be expected for their role.",
        "doubt_score": 0.4,
        "final_severity": "REVIEW",
        "recommendation": "Verify access patterns with direct manager before escalating.",
        "breach_impact": f"If compromised, attacker could access: {', '.join(user_profile.get('systems_access', []))}.",
    }


def stream_narrative(user_profile: dict[str, Any], flagged_events: list[dict[str, Any]], feedback_context: dict[str, Any]):
    """Streams the stub narrative as one SSE chunk so the frontend EventSource path is exercised."""
    narrative = generate_narrative(user_profile, flagged_events, feedback_context)
    full_text = f"PROSECUTION:\n{narrative['prosecution']}\n\nDEVIL'S ADVOCATE:\n{narrative['devils_advocate']}"
    yield f"data: {full_text}\n\n"
    yield "data: [DONE]\n\n"
