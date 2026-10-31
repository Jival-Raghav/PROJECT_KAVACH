"""
backend/security/injection_detect.py — Prompt Injection & Adversarial Payload Detector.

Detects and neutralizes indirect prompt injections, role-spoofing tags,
instruction overrides, JSON metric forgery, and obfuscated base64 attacks.
"""
from __future__ import annotations

import base64
import re
from pydantic import BaseModel, Field

# High-confidence injection and role-spoofing patterns
INJECTION_PATTERNS = [
    # Role tags
    (r"(?i)(\[system\]|\[inst\]|<system>|<assistant>|<user>|<prompt>|<<sys>>)", "ROLE_TAG_SPOOF"),
    # Direct instruction overrides
    (r"(?i)(ignore (all )?(previous|prior) (instructions|prompts|rules))", "INSTRUCTION_OVERRIDE"),
    (r"(?i)(disregard (all )?(previous|prior|above) (text|context|instructions))", "INSTRUCTION_OVERRIDE"),
    (r"(?i)(bypass (all )?(security|detection|rules|filters))", "SECURITY_BYPASS_ATTEMPT"),
    (r"(?i)(you are (now )?no longer (a security|an assistant|bound))", "JAILBREAK_ATTEMPT"),
    # Metric and verdict forgery
    (r"(?i)(mark (this )?(alert|case|incident|finding|user) as (benign|safe|clean|authorized))", "VERDICT_FORGERY"),
    (r"(?i)(set (the )?(severity|risk|threat)( level)? to (low|none|zero|0))", "SEVERITY_TAMPERING"),
    (r"(?i)(set doubt_score to (1\.0|1|0\.99))", "DOUBT_SCORE_FORGERY"),
    (r"(?i)(\"verdict\"\s*:\s*\"(MITIGATED_BENIGN|BENIGN)\")", "JSON_VERDICT_INJECTION"),
    (r"(?i)(\"doubt_score\"\s*:\s*1(\.0)?)", "JSON_METRIC_INJECTION"),
    # Forged tool calls
    (r"(?i)(\"tool\"\s*:\s*\"(was_on_call|change_ticket_covering|approved_exception)\")", "TOOL_CALL_INJECTION"),
]

# Base64 string pattern (>40 chars)
BASE64_PATTERN = re.compile(r"\b([A-Za-z0-9+/]{40,}={0,2})\b")


class InjectionReport(BaseModel):
    is_injection: bool = False
    confidence: float = 0.0
    matched_threats: list[str] = Field(default_factory=list)
    sanitized_text: str
    original_text: str


def detect_and_redact_injection(text: str) -> InjectionReport:
    """
    Scans text for adversarial prompt injection patterns.
    If detected, redacts offending snippets with [REDACTED:suspected-injection].
    """
    if not text:
        return InjectionReport(sanitized_text="", original_text="")

    matched_threats = []
    redacted = str(text)

    # 1. Regex pattern matching
    for pattern, threat_type in INJECTION_PATTERNS:
        matches = list(re.finditer(pattern, redacted))
        if matches:
            matched_threats.append(threat_type)
            redacted = re.sub(pattern, "[REDACTED:suspected-injection]", redacted)

    # 2. Base64 payload inspection
    for b64_match in BASE64_PATTERN.finditer(text):
        b64_str = b64_match.group(1)
        try:
            decoded = base64.b64decode(b64_str, validate=True).decode("utf-8", errors="ignore")
            # If decoded text contains instruction overrides
            for pattern, threat_type in INJECTION_PATTERNS:
                if re.search(pattern, decoded):
                    matched_threats.append(f"BASE64_{threat_type}")
                    redacted = redacted.replace(b64_str, "[REDACTED:obfuscated-injection]")
                    break
        except Exception:
            pass

    unique_threats = list(set(matched_threats))
    is_injection = len(unique_threats) > 0
    confidence = min(1.0, 0.4 + (len(unique_threats) * 0.3)) if is_injection else 0.0

    return InjectionReport(
        is_injection=is_injection,
        confidence=round(confidence, 2),
        matched_threats=unique_threats,
        sanitized_text=redacted,
        original_text=text,
    )
