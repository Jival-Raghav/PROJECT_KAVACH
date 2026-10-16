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
from typing import Any, Iterator

from llm.client import LLMClient, ProviderError, get_da_client, get_prosecutor_client
from llm.prompts import (
    apply_doubt_gate,
    build_devils_advocate_messages,
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
    if _prosecutor_error is not None:
        return None
    try:
        _prosecutor_client = get_prosecutor_client()
        return _prosecutor_client
    except ProviderError as exc:
        _prosecutor_error = str(exc)
        logger.error("Prosecutor client init failed: %s", exc)
        return None


def _get_da() -> LLMClient | None:
    global _da_client, _da_error
    if _da_client is not None:
        return _da_client
    if _da_error is not None:
        return None
    try:
        _da_client = get_da_client()
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


def _parse_json_response(raw: str) -> dict[str, Any]:
    """Tolerantly extracts a JSON object from LLM output (strips markdown fences)."""
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1:
        try:
            return json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("Could not parse LLM JSON: %s", raw[:200])
        return {}


def generate_narrative(
    profile: dict[str, Any],
    flagged_events: list[dict[str, Any]],
    feedback_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Runs the two-pass workflow:
      - Pass 1: Prosecutor (LM Studio) builds the accusation
      - Pass 2: Devil's Advocate (Ollama) challenges it

    Raises ProviderError with human-readable message if either LLM is unavailable.
    """
    prosecutor = _get_prosecutor()
    da = _get_da()

    if prosecutor is None:
        raise ProviderError(
            f"Prosecutor LLM (Pass 1) is not available. {_prosecutor_error or 'Check PROSECUTOR_PROVIDER in .env'}"
        )
    if da is None:
        raise ProviderError(
            f"Devil's Advocate LLM (Pass 2) is not available. {_da_error or 'Check DA_PROVIDER in .env — run `ollama serve` to start Ollama'}"
        )

    username = profile.get("username", "unknown")
    logger.info("Generating narrative for %s [prosecutor=%s, da=%s]",
                username, prosecutor.name(), da.name())

    # ── Pass 1: Prosecutor (LM Studio) ─────────────────────────────────────
    prosecutor_messages = build_prosecutor_messages(profile, flagged_events)
    try:
        prosecutor_raw = prosecutor.chat(prosecutor_messages, temperature=0.3, max_tokens=800)
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError(f"Prosecutor LLM call failed: {exc}") from exc

    prosecution_result = _parse_json_response(prosecutor_raw)
    prosecution_text = prosecution_result.get(
        "prosecution",
        f"{username} has suspicious access patterns requiring investigation."
    )
    prosecution_severity = prosecution_result.get("severity", "REVIEW")
    key_evidence = prosecution_result.get("key_evidence", [])
    breach_impact = prosecution_result.get(
        "breach_impact",
        f"Systems at risk: {', '.join(profile.get('systems_access', [])[:5])}."
    )

    # ── Pass 2: Devil's Advocate (Ollama) ───────────────────────────────────
    da_messages = build_devils_advocate_messages(profile, flagged_events, prosecution_result)
    try:
        da_raw = da.chat(da_messages, temperature=0.4, max_tokens=600)
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError(f"Devil's Advocate LLM call failed: {exc}") from exc

    da_result = _parse_json_response(da_raw)
    challenge_text = da_result.get(
        "challenge",
        "Insufficient context to mount a defence. Proceed with investigation."
    )
    doubt_score = float(da_result.get("doubt_score", 0.4))
    doubt_score = max(0.0, min(1.0, doubt_score))
    recommendation = da_result.get(
        "final_recommendation",
        "Verify access patterns with direct manager before escalating."
    )

    # ── Apply DA gate ───────────────────────────────────────────────────────
    final_severity = apply_doubt_gate(prosecution_severity, doubt_score)

    # Analyst suppression override
    if feedback_context.get("suppressed"):
        final_severity = "SUPPRESSED"

    narrative: dict[str, Any] = {
        "prosecution": prosecution_text,
        "devils_advocate": challenge_text,
        "doubt_score": round(doubt_score, 3),
        "final_severity": final_severity,
        "recommendation": recommendation,
        "breach_impact": breach_impact,
        "prosecutor_model": prosecutor.name(),
        "da_model": da.name(),
    }

    logger.info("Narrative done for %s — severity: %s, doubt: %.2f",
                username, final_severity, doubt_score)
    return narrative


def stream_narrative(
    profile: dict[str, Any],
    flagged_events: list[dict[str, Any]],
    feedback_context: dict[str, Any],
) -> Iterator[str]:
    """
    Streams the two-pass narrative as SSE events.
    Pass 1 (Prosecutor / LM Studio) and Pass 2 (DA / Ollama) stream in sequence.
    ProviderError on either pass yields a structured SSE error event.
    """
    prosecutor = _get_prosecutor()
    da = _get_da()

    if prosecutor is None:
        yield f"data: ERROR [Prosecutor]: {_prosecutor_error or 'LM Studio not running'}\n\n"
        yield "data: [DONE]\n\n"
        return

    if da is None:
        yield f"data: ERROR [Devil's Advocate]: {_da_error or 'Ollama not running — run `ollama serve`'}\n\n"
        yield "data: [DONE]\n\n"
        return

    # ── Stream Pass 1: Prosecutor (LM Studio) ───────────────────────────────
    yield f"data: [PROSECUTOR — {prosecutor.name()}]\n\n"
    prosecutor_messages = build_prosecutor_messages(profile, flagged_events)
    prosecution_chunks: list[str] = []

    try:
        for chunk in prosecutor.stream(prosecutor_messages, temperature=0.3, max_tokens=800):
            prosecution_chunks.append(chunk)
            yield f"data: {chunk}\n\n"
    except ProviderError as exc:
        yield f"data: ERROR [Prosecutor]: {exc}\n\n"
        yield "data: [DONE]\n\n"
        return

    prosecution_result = _parse_json_response("".join(prosecution_chunks))

    # ── Stream Pass 2: Devil's Advocate (Ollama) ────────────────────────────
    yield f"data: [DEVIL'S ADVOCATE — {da.name()}]\n\n"
    da_messages = build_devils_advocate_messages(profile, flagged_events, prosecution_result)

    try:
        for chunk in da.stream(da_messages, temperature=0.4, max_tokens=600):
            yield f"data: {chunk}\n\n"
    except ProviderError as exc:
        yield f"data: ERROR [Devil's Advocate]: {exc}\n\n"

    yield "data: [DONE]\n\n"
