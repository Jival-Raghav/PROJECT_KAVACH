"""
llm/narrator.py
Real two-pass LLM narrator with Devil's Advocate workflow using TWO separate models.

  Pass 1 (Prosecutor)      → PROSECUTOR_PROVIDER  (default: LM Studio)
  Pass 2 (Devil's Advocate)→ DA_PROVIDER           (default: Ollama)

Both clients are lazily initialised on first request and cached separately.
Clear ProviderError with actionable messages if either is unavailable.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Iterator

from llm.client import LLMClient, ProviderError, get_da_client, get_prosecutor_client
from llm.jsonutil import parse_llm_json
from llm.prompts import (
    apply_doubt_gate,
    build_devils_advocate_messages,
    build_inference_messages,
    build_prosecutor_messages,
)

logger = logging.getLogger(__name__)

# ─── Lazy client cache ────────────────────────────────────────────────────────
# Each pass uses its own client instance, cached after first successful init.
_prosecutor_client: LLMClient | None = None
_prosecutor_error: str | None = None

_da_client: LLMClient | None = None
_da_error: str | None = None



def _get_prosecutor() -> LLMClient | None:
    global _prosecutor_client, _prosecutor_error
    if _prosecutor_client is not None:
        return _prosecutor_client
    try:
        _prosecutor_client = get_prosecutor_client()
        _prosecutor_error = None
        return _prosecutor_client
    except ProviderError as exc:
        _prosecutor_error = str(exc)
        logger.error("Prosecutor client init failed: %s", exc)
        return None


def _get_da() -> LLMClient | None:
    global _da_client, _da_error
    if _da_client is not None:
        return _da_client
    try:
        _da_client = get_da_client()
        _da_error = None
        return _da_client
    except ProviderError as exc:
        _da_error = str(exc)
        logger.error("Devil's Advocate client init failed: %s", exc)
        return None


def get_provider_status() -> dict[str, Any]:
    """
    Returns status of both LLM clients.
    Called by /status and /llm-status endpoints.
    """
    prosecutor = _get_prosecutor()
    da = _get_da()
    return {
        "prosecutor": {
            "available": prosecutor is not None,
            "provider": prosecutor.name() if prosecutor else None,
            "error": _prosecutor_error,
        },
        "devils_advocate": {
            "available": da is not None,
            "provider": da.name() if da else None,
            "error": _da_error,
        },
        "llm_available": prosecutor is not None and da is not None,
    }


def _sse(chunk: str) -> str:
    """Frame text as one SSE event; embedded newlines become extra `data:` lines
    (EventSource rejoins them with \\n), so model output can't break the framing."""
    return "".join(f"data: {line}\n" for line in chunk.replace("\r", "").split("\n")) + "\n"


def _parse_json_response(raw: str) -> dict[str, Any]:
    """Tolerantly extracts a JSON object from LLM output (strips markdown fences)."""
    parsed = parse_llm_json(raw)
    if parsed is None:
        logger.warning("Could not parse LLM JSON: %s", (raw or "")[:200])
        return {}
    return parsed


_CLAIM_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "REVIEW", "low": "INFORMATIONAL"}
_SEVERITY_RANK = ["INFORMATIONAL", "REVIEW", "HIGH", "CRITICAL"]

# Reasoning models spend part of max_tokens on hidden thinking; leave generous headroom.
_PROSECUTOR_TOKENS = 2500
_DA_TOKENS = 2000
_INFERENCE_TOKENS = 2500
_MAX_ATTEMPTS = 3


def _normalize_prosecution(result: dict[str, Any]) -> dict[str, Any]:
    """Adapt the v2 prosecutor schema ({"claims": [...]}) to the narrator's
    {"prosecution", "severity", "key_evidence"} shape. Legacy-shaped results pass through."""
    claims = result.get("claims")
    if not isinstance(claims, list) or not claims:
        return result
    claims = [c for c in claims if isinstance(c, dict)]
    severities = [_CLAIM_SEVERITY.get(str(c.get("severity", "")).lower(), "REVIEW") for c in claims]
    return {
        **result,
        "prosecution": " ".join(str(c.get("statement", "")).strip() for c in claims if c.get("statement")),
        "severity": max(severities, key=_SEVERITY_RANK.index) if severities else "REVIEW",
        "key_evidence": [str(c["statement"]) for c in claims if c.get("statement")],
    }


def _retry_delay(exc: Exception, attempt: int) -> float:
    """Honour a provider's 'try again in 2.5s' hint on 429s, else back off exponentially."""
    m = re.search(r"try again in ([\d.]+)\s*(ms|s|m)\b", str(exc))
    if m:
        secs = float(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60}[m.group(2)]
        return min(secs + 0.5, 20.0)
    return float(2 ** attempt)


def _chat_json(client: LLMClient, messages: list[dict[str, str]], *, temperature: float,
               max_tokens: int, validate) -> dict[str, Any] | None:
    """Call the model until `validate(parsed)` yields a usable dict, or give up (None)."""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            raw = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
        except Exception as exc:  # provider/network/rate-limit
            logger.warning("LLM call failed (attempt %d/%d): %s", attempt, _MAX_ATTEMPTS, exc)
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_retry_delay(exc, attempt))
            continue
        parsed = parse_llm_json(raw)
        if parsed is not None and parsed.get("claims") == []:
            logger.info("Model found nothing to prosecute; not retrying")
            return None
        usable = validate(parsed) if parsed is not None else None
        if usable:
            return usable
        logger.warning("Unusable LLM output (attempt %d/%d): %r", attempt, _MAX_ATTEMPTS, (raw or "")[:200])
    return None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, dict):
            item = " — ".join(str(v) for v in item.values() if v)
        item = str(item).strip()
        if item:
            out.append(item)
    return out


def _severity_from_risk(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "REVIEW"
    return "CRITICAL" if s >= 75 else "HIGH" if s >= 55 else "REVIEW" if s >= 35 else "INFORMATIONAL"


# ─── Pass 1: Prosecutor ──────────────────────────────────────────────────────

def _validate_prosecution(parsed: dict[str, Any]) -> dict[str, Any] | None:
    result = _normalize_prosecution(parsed)
    text = _text(result.get("prosecution"))
    if not text:
        return None
    severity = str(result.get("severity", "")).upper()
    return {
        **result,
        "prosecution": text,
        "severity": severity if severity in _SEVERITY_RANK else "REVIEW",
        "key_evidence": _str_list(result.get("key_evidence")),
    }


def _fallback_prosecution(profile: dict[str, Any], flagged_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Grounded prosecution built from the detection output when the model yields nothing usable."""
    name = profile.get("username", "unknown")
    evidence: list[str] = []
    for key, label in (("flags", "Risk flag"), ("sod_violations", "Separation-of-duties violation"),
                       ("compliance_gaps", "Compliance gap")):
        evidence += [f"{label}: {item}" for item in _str_list(profile.get(key))]
    for e in flagged_events[:5]:
        evidence.append(
            f"{e.get('action', 'activity')} on {e.get('resource', 'a resource')} "
            f"({e.get('resource_sensitivity', 'unknown')} sensitivity) at {e.get('timestamp', 'unknown time')}"
        )
    risk = profile.get("risk_score")
    lead = (f"{name} ({profile.get('job_title', 'staff')}, {profile.get('department', 'unknown department')}) "
            f"carries a risk score of {risk}.")
    body = " ".join(evidence[:6]) if evidence else "No individual rule fired, but the behavioural model scores this account above baseline."
    return {
        "prosecution": f"{lead} {body}",
        "severity": _severity_from_risk(risk),
        "key_evidence": evidence,
    }


def _run_prosecution(client: LLMClient | None, profile, flagged_events, breach_summary) -> tuple[dict[str, Any], bool]:
    """Returns (prosecution_result, from_llm)."""
    if client is not None:
        messages = build_prosecutor_messages(profile, flagged_events, breach_summary)
        result = _chat_json(client, messages, temperature=0.3, max_tokens=_PROSECUTOR_TOKENS,
                            validate=_validate_prosecution)
        if result:
            return result, True
    return _fallback_prosecution(profile, flagged_events), False


# ─── Pass 2: Devil's Advocate ────────────────────────────────────────────────

def _validate_defence(parsed: dict[str, Any]) -> dict[str, Any] | None:
    challenge = _text(parsed.get("challenge"))
    if not challenge:
        return None
    try:
        doubt = max(0.0, min(1.0, float(parsed.get("doubt_score", 0.4))))
    except (TypeError, ValueError):
        doubt = 0.4
    return {
        **parsed,
        "challenge": challenge,
        "doubt_score": doubt,
        "final_recommendation": _text(parsed.get("final_recommendation"))
        or "Verify access patterns with the user's manager before escalating.",
    }


def _fallback_defence(profile: dict[str, Any]) -> dict[str, Any]:
    name = profile.get("username", "the user")
    return {
        "challenge": (
            f"The case against {name} rests on behavioural statistics rather than proof of intent. "
            f"As {profile.get('job_title', 'staff')} in {profile.get('department', 'their department')}, "
            "the flagged access may reflect routine duties, on-call work or an approved change window. "
            "Confirm with the user's manager and the change/on-call records before treating this as malicious."
        ),
        "doubt_score": 0.4,
        "final_recommendation": "Verify access patterns with the user's manager before escalating.",
    }


def _run_defence(client: LLMClient | None, profile, flagged_events, prosecution_result) -> tuple[dict[str, Any], bool]:
    if client is not None:
        messages = build_devils_advocate_messages(profile, flagged_events, prosecution_result)
        result = _chat_json(client, messages, temperature=0.4, max_tokens=_DA_TOKENS,
                            validate=_validate_defence)
        if result:
            return result, True
    return _fallback_defence(profile), False


# ─── Assembly ────────────────────────────────────────────────────────────────

def _breach_summary(profile: dict[str, Any], all_profiles: list[dict[str, Any]]) -> str:
    try:
        from models.breach_simulator import simulate_breach, summarise_for_prompt
        return summarise_for_prompt(simulate_breach(profile, all_profiles))
    except Exception as exc:
        logger.warning("Breach simulation failed, continuing without it: %s", exc)
        return ""


def _assemble(profile, feedback_context, prosecution_result, defence_result,
              prosecutor: LLMClient | None, da: LLMClient | None, degraded: bool) -> dict[str, Any]:
    from models.feedback_model import apply_feedback_calibration

    username = profile.get("username", "unknown")
    doubt_score = apply_feedback_calibration(profile, defence_result["doubt_score"])
    final_severity = apply_doubt_gate(prosecution_result["severity"], doubt_score)
    if feedback_context.get("suppressed"):
        final_severity = "SUPPRESSED"
    systems = profile.get("systems") or []
    narrative = {
        "prosecution": prosecution_result["prosecution"],
        "devils_advocate": defence_result["challenge"],
        "doubt_score": round(float(doubt_score), 3),
        "final_severity": final_severity,
        "recommendation": defence_result["final_recommendation"],
        "breach_impact": _text(prosecution_result.get("breach_impact"))
        or f"Systems at risk: {', '.join(str(s) for s in list(systems)[:5])}.",
        "prosecutor_model": prosecutor.name() if prosecutor else "deterministic-fallback",
        "da_model": da.name() if da else "deterministic-fallback",
        "degraded": degraded,
    }
    logger.info("Narrative done for %s — severity: %s, doubt: %.2f, degraded=%s",
                username, final_severity, narrative["doubt_score"], degraded)
    return narrative


def narrative_is_valid(narrative: Any) -> bool:
    """A cached narrative is reusable only if both sides produced real, non-degraded text."""
    return (
        isinstance(narrative, dict)
        and bool(_text(narrative.get("prosecution")))
        and bool(_text(narrative.get("devils_advocate")))
        and not narrative.get("degraded")
        and not _text(narrative.get("devils_advocate")).startswith("Insufficient context to mount a defence")
    )


def generate_narrative(
    profile: dict[str, Any],
    flagged_events: list[dict[str, Any]],
    feedback_context: dict[str, Any],
    all_profiles: list[dict[str, Any]] = [],
) -> dict[str, Any]:
    """Runs both passes and returns the narrative dict. Never raises on model problems:
    a pass the model cannot complete falls back to grounded deterministic text (degraded=True)."""
    breach_summary = _breach_summary(profile, all_profiles)
    prosecutor, da = _get_prosecutor(), _get_da()
    prosecution, p_ok = _run_prosecution(prosecutor, profile, flagged_events, breach_summary)
    defence, d_ok = _run_defence(da, profile, flagged_events, prosecution)
    return _assemble(profile, feedback_context, prosecution, defence, prosecutor, da, not (p_ok and d_ok))


def _prose_chunks(text: str, words: int = 4) -> Iterator[str]:
    parts = re.findall(r"\S+\s*", text)
    for i in range(0, len(parts), words):
        yield "".join(parts[i:i + words])


def stream_narrative(
    profile: dict[str, Any],
    flagged_events: list[dict[str, Any]],
    feedback_context: dict[str, Any],
    all_profiles: list[dict[str, Any]] = [],
    on_complete=None,
) -> Iterator[str]:
    """
    Streams the two-pass narrative as SSE. Each pass is generated once (blocking, validated,
    retried), then its *prose* is streamed — raw model JSON never reaches the UI. A non-degraded
    result is stored on profile["narrative"] (degraded ones are retried next time).
    """
    try:
        breach_summary = _breach_summary(profile, all_profiles)
        prosecutor, da = _get_prosecutor(), _get_da()

        yield _sse(f"[PROSECUTOR — {prosecutor.name() if prosecutor else 'deterministic-fallback'}]")
        prosecution, p_ok = _run_prosecution(prosecutor, profile, flagged_events, breach_summary)
        for chunk in _prose_chunks(prosecution["prosecution"]):
            yield _sse(chunk)

        yield _sse(f"[DEVIL'S ADVOCATE — {da.name() if da else 'deterministic-fallback'}]")
        defence, d_ok = _run_defence(da, profile, flagged_events, prosecution)
        for chunk in _prose_chunks(defence["challenge"]):
            yield _sse(chunk)

        narrative = _assemble(profile, feedback_context, prosecution, defence, prosecutor, da, not (p_ok and d_ok))
        profile["narrative"] = narrative  # degraded ones are regenerated on the next request
        if on_complete:
            on_complete(narrative)  # persist before [DONE] so an immediate verdict request finds it
    except Exception as exc:  # never leave the client with a silent empty stream
        logger.exception("Narrative stream failed")
        yield _sse(f"ERROR [Narrative]: {exc}")
    yield _sse("[DONE]")


# ─── Pass 3: Inference / verdict ─────────────────────────────────────────────

_ACTIONS = ("ESCALATE", "INVESTIGATE", "MONITOR", "DISMISS")
_CONFIDENCE = ("HIGH", "MEDIUM", "LOW")


def _validate_inference(parsed: dict[str, Any]) -> dict[str, Any] | None:
    what = _text(parsed.get("what_happened"))
    action = str(parsed.get("recommended_action", "")).strip().upper()
    if not what or action not in _ACTIONS:
        return None
    confidence = str(parsed.get("confidence", "")).strip().upper()
    return {
        "recommended_action": action,
        "confidence": confidence if confidence in _CONFIDENCE else "MEDIUM",
        "what_happened": what,
        "key_findings": _str_list(parsed.get("key_findings")),
        "remediation_steps": _str_list(parsed.get("remediation_steps")),
        "rationale": _text(parsed.get("rationale")),
    }


def _fallback_inference(profile, prosecution_text, da_text, doubt_score, final_severity) -> dict[str, Any]:
    sev = (final_severity or "REVIEW").upper()
    doubt = doubt_score if isinstance(doubt_score, (int, float)) else 0.4
    action = ("ESCALATE" if sev in ("CRITICAL", "HIGH")
              else "DISMISS" if sev == "SUPPRESSED" or (sev == "INFORMATIONAL" and doubt >= 0.85)
              else "MONITOR" if sev == "INFORMATIONAL" else "INVESTIGATE")
    steps = {
        "ESCALATE": ["Open a Tier-2 SOC case with the evidence dossier.",
                     "Review and revoke unneeded privileged access for the account."],
        "INVESTIGATE": ["Confirm the flagged activity with the user's manager.",
                        "Check change tickets and on-call schedules for the flagged window."],
        "MONITOR": ["Keep the account on the watchlist and re-score after the next pipeline run."],
        "DISMISS": ["Record the alert as a false positive."],
    }[action]
    return {
        "recommended_action": action,
        "confidence": "LOW",
        "what_happened": prosecution_text[:400] or f"{profile.get('username', 'The user')} was flagged by behavioural detection.",
        "key_findings": [f"Final severity {sev} with doubt {doubt:.0%}."],
        "remediation_steps": steps,
        "rationale": "Generated from the recorded severity and doubt score because the model returned no usable verdict.",
    }


def stream_inference(
    profile: dict[str, Any],
    prosecution_text: str,
    da_text: str,
    doubt_score: float | None = None,
    final_severity: str | None = None,
) -> Iterator[str]:
    """
    Pass 3 — Inference. Synthesises prosecutor + DA into a verdict. The result is validated
    and emitted as ONE well-formed JSON line, so the UI always gets parseable output.
    """
    prosecutor = _get_prosecutor()
    yield _sse(f"[INFERENCE — {prosecutor.name() if prosecutor else 'deterministic-fallback'}]")
    try:
        result = None
        if prosecutor is not None:
            messages = build_inference_messages(
                profile=profile, prosecution_text=prosecution_text, da_text=da_text,
                doubt_score=doubt_score, final_severity=final_severity,
            )
            result = _chat_json(prosecutor, messages, temperature=0.25,
                                max_tokens=_INFERENCE_TOKENS, validate=_validate_inference)
        if result is None:
            result = _fallback_inference(profile, prosecution_text, da_text, doubt_score, final_severity)
        yield _sse(json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        logger.exception("Inference stream failed")
        yield _sse(f"ERROR [Inference]: {exc}")
    yield _sse("[DONE]")
