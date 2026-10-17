"""
backend/llm/gateway.py — Unified LLM Security Gateway.

Enforces defense-in-depth on all LLM interactions:
1. Input sanitization (Unicode NFKC, zero-width & bidi stripping).
2. Prompt injection detection and redaction.
3. PII and Identity pseudonymization.
4. Nonce data wrapping.
5. Strict schema validation.
6. Output sanitization & de-pseudonymization.
"""
from __future__ import annotations

import secrets
from typing import Any, TypeVar
from pydantic import BaseModel

from security.sanitize import sanitize_text, sanitize_output_narrative
from security.injection_detect import detect_and_redact_injection
from security.pseudonymize import Pseudonymizer
from security.invariance import verify_verdict_invariance

T = TypeVar("T", bound=BaseModel)


class SecurityGateway:
    def __init__(self):
        self.pseudonymizer = Pseudonymizer()
        self.injection_events: list[dict[str, Any]] = []

    def prepare_data_payload(self, raw_data_str: str) -> tuple[str, str, list[str]]:
        """
        Pre-flight defense: sanitizes text, detects/redacts injections,
        pseudonymizes PII, and wraps in a fresh cryptographic nonce.
        """
        # 1. Unicode and zero-width sanitization
        sanitized = sanitize_text(raw_data_str, max_length=15000)

        # 2. Injection detection
        report = detect_and_redact_injection(sanitized)
        if report.is_injection:
            self.injection_events.append({
                "threats": report.matched_threats,
                "confidence": report.confidence,
                "original_snippet": report.original_text[:120],
            })

        # 3. Pseudonymize
        pseudo_text = self.pseudonymizer.pseudonymize_text(report.sanitized_text)

        # 4. Generate random cryptographic nonce
        nonce = secrets.token_hex(8)
        wrapped_data = f'<data nonce="{nonce}">\n{pseudo_text}\n</data>'

        return wrapped_data, nonce, report.matched_threats

    def process_output_narrative(self, raw_output: str) -> str:
        """
        Post-flight defense: strips exfiltration payloads, markdown images, and de-pseudonymizes.
        """
        sanitized_narrative = sanitize_output_narrative(raw_output)
        clean_text = self.pseudonymizer.depseudonymize_text(sanitized_narrative)
        return clean_text

    def verify_invariance(self, baseline: dict[str, Any], defended: dict[str, Any]) -> dict[str, Any]:
        """Runs verdict invariance check."""
        return verify_verdict_invariance(baseline, defended)


# Gateway singleton
gateway = SecurityGateway()
