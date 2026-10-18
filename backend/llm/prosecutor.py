"""backend/llm/prosecutor.py
Pass 1: Security Prosecution Agent for Kavach v2.

Formulates structured, evidence-grounded claims against an accused user profile.
Deterministic security violations (Separation of Duties, Leaver-Active, Stale Privileged)
are tagged with hard_rule=True and cannot be dismissed by downstream defense counsel.
"""
from __future__ import annotations

import logging
from typing import Any

from config import get_settings
from core.models import CanonicalBundle, CanonicalEvent
from llm.client import get_prosecutor_client
from llm.jsonutil import parse_llm_json
from llm.prompts import build_prosecutor_messages
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ProsecutorClaim(BaseModel):
    claim_id: str
    type: str  # after_hours | sensitive_access | sod_conflict | stale_privileged | orphan | privilege_creep | geo_anomaly | peer_outlier | mass_access | failed_logins
    statement: str
    event_ids: list[str] = Field(default_factory=list)
    severity: str = "medium"  # low | medium | high | critical
    hard_rule: bool = False


def _is_hard_rule_finding(finding: dict[str, Any], profile: dict[str, Any]) -> bool:
    """Enforces non-negotiable hard rules that cannot be dismissed."""
    f_type = str(finding.get("type", "")).lower()
    f_id = str(finding.get("id", "")).upper()

    if "sod" in f_type or f_id.startswith("SOD_"):
        return True
    if "stale_priv" in f_id or f_type == "stale_privileged":
        return True
    if str(profile.get("employment_status", "")).lower() in ("terminated", "disabled"):
        return True
    if finding.get("hard_rule"):
        return True
    return False


def run_deterministic_prosecutor(
    profile: dict[str, Any],
    findings: list[dict[str, Any]],
    events: list[CanonicalEvent],
) -> list[ProsecutorClaim]:
    """Fallback deterministic claim generator when LLM is offline, cached, or in replay mode."""
    claims: list[ProsecutorClaim] = []
    claim_idx = 1

    ev_id_map = [e.event_id for e in events if e.event_id]

    for f in findings:
        cid = f"c{claim_idx}"
        claim_idx += 1
        f_type = f.get("type", "anomaly")
        f_name = f.get("name", "Security Anomaly")
        f_desc = f.get("description", "Suspicious pattern detected")
        f_sev = f.get("severity", "medium").lower()
        is_hard = _is_hard_rule_finding(f, profile)

        # Normalize claim type
        norm_type = "anomaly"
        if "sod" in f_type:
            norm_type = "sod_conflict"
        elif "leaver" in f_type:
            norm_type = "leaver_active"
        elif "stale" in f_type:
            norm_type = "stale_privileged"
        elif "sensitive" in f_type:
            norm_type = "sensitive_access"
        elif "creep" in f_type:
            norm_type = "privilege_creep"
        elif "peer" in f_type:
            norm_type = "peer_outlier"
        elif "service" in f_type:
            norm_type = "service_abuse"

        claims.append(
            ProsecutorClaim(
                claim_id=cid,
                type=norm_type,
                statement=f"{f_name}: {f_desc}",
                event_ids=ev_id_map[:5],
                severity=f_sev if f_sev in ("low", "medium", "high", "critical") else "medium",
                hard_rule=is_hard,
            )
        )

    # Check for impossible travel
    if profile.get("impossible_travel_flag") == 1.0 or any("travel" in str(fl).lower() for fl in profile.get("flags", [])):
        claims.append(
            ProsecutorClaim(
                claim_id=f"c{claim_idx}",
                type="geo_anomaly",
                statement="Impossible travel speed detected across distinct geographic coordinates within a short time window.",
                event_ids=ev_id_map[:3],
                severity="high",
                hard_rule=False,
            )
        )
        claim_idx += 1

    # Check for failed login surges
    if float(profile.get("failed_login_ratio", 0.0)) > 0.40:
        claims.append(
            ProsecutorClaim(
                claim_id=f"c{claim_idx}",
                type="failed_logins",
                statement=f"High failure rate ({int(float(profile.get('failed_login_ratio', 0.0))*100)}%) indicates potential brute-force or credential probing.",
                event_ids=ev_id_map[:5],
                severity="medium",
                hard_rule=False,
            )
        )
        claim_idx += 1

    # Default fallback claim if user has high risk score but no specific rule fired
    if not claims and float(profile.get("risk_score", 0.0)) >= 40.0:
        claims.append(
            ProsecutorClaim(
                claim_id="c1",
                type="peer_outlier",
                statement=f"Multivariate Isolation Forest anomaly score ({profile.get('risk_score')}) significantly deviates from organizational baseline.",
                event_ids=ev_id_map[:5],
                severity="high" if float(profile.get("risk_score", 0.0)) >= 60.0 else "medium",
                hard_rule=False,
            )
        )

    return claims


def run_prosecutor(
    bundle: CanonicalBundle,
    profile: dict[str, Any],
    findings: list[dict[str, Any]],
    events: list[CanonicalEvent],
    use_llm: bool = True,
) -> list[ProsecutorClaim]:
    """Executes Pass 1 (Prosecutor) using LLM if available, with robust deterministic fallback."""
    cfg = get_settings()
    if not use_llm or cfg.LLM_REPLAY_ONLY or cfg.PROSECUTOR_PROVIDER.value == "none":
        return run_deterministic_prosecutor(profile, findings, events)

    try:
        client = get_prosecutor_client()
        flagged_events_dicts = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "action": e.action,
                "resource": e.resource,
                "system": e.system,
                "resource_sensitivity": e.resource_sensitivity,
                "success": e.success,
                "source_ip": e.source_ip,
            }
            for e in events[:20]
        ]
        messages = build_prosecutor_messages(profile, findings, flagged_events_dicts)
        parsed = None
        for _ in range(2):
            parsed = parse_llm_json(client.chat(messages, temperature=0.2, max_tokens=3000))
            if parsed and isinstance(parsed.get("claims"), list) and parsed["claims"]:
                break
        raw_claims = [c for c in (parsed or {}).get("claims", []) if isinstance(c, dict)]

        claims: list[ProsecutorClaim] = []
        for c in raw_claims:
            is_hard = c.get("hard_rule", False)
            # Re-verify hard rule constraint in Python
            for f in findings:
                if _is_hard_rule_finding(f, profile):
                    if f.get("name", "").lower() in c.get("statement", "").lower():
                        is_hard = True
                        break

            claims.append(
                ProsecutorClaim(
                    claim_id=c.get("claim_id", f"c{len(claims)+1}"),
                    type=c.get("type", "anomaly"),
                    statement=c.get("statement", ""),
                    event_ids=c.get("event_ids", []),
                    severity=(str(c.get("severity", "medium")).lower()
                              if str(c.get("severity", "medium")).lower() in ("low", "medium", "high", "critical")
                              else "medium"),
                    hard_rule=is_hard,
                )
            )

        if claims:
            return claims

    except Exception as exc:
        logger.warning("Prosecutor LLM call failed, falling back to deterministic: %s", exc)

    return run_deterministic_prosecutor(profile, findings, events)
