"""Incident risk score (B-1): how far the attacker got matters more than alert volume."""
from __future__ import annotations

import math

from killchain.models import Incident

_SEV_WEIGHT = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
_LAST_STAGE = 6  # index of "Actions on Objectives"


def score_incident(inc: Incident) -> tuple[float, str]:
    dets = inc.detections
    progression = max(d.technique.stage_index for d in dets) / _LAST_STAGE
    breadth = min(1.0, len({d.technique.tactic for d in dets}) / 4)
    succeeded = 1.0 if any(d.outcome != "blocked" for d in dets) else 0.0
    severity = max(_SEV_WEIGHT[d.severity] for d in dets)
    volume = min(1.0, math.log10(max(1, inc.raw_alert_count)) / 4)
    score = round(35 * progression + 20 * breadth + 20 * succeeded + 15 * severity + 10 * volume, 1)
    level = ("critical" if score >= 80 else "high" if score >= 60
             else "medium" if score >= 40 else "low")
    return score, level


def rank(incidents: list[Incident]) -> list[Incident]:
    for inc in incidents:
        inc.risk_score, inc.severity = score_incident(inc)
    return sorted(incidents, key=lambda i: (-i.risk_score, i.first_seen))
