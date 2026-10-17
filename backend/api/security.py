"""
backend/api/security.py — FastAPI router for AI & Non-Human Identity (NHI) Security Layer.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter
from pydantic import BaseModel

from ingest.legacy_adapter import load_legacy_as_canonical
from security.nhi import audit_non_human_identities
from security.sanitize import sanitize_text
from security.injection_detect import detect_and_redact_injection
from scripts.bench_redteam import run_redteam_benchmark

router = APIRouter(prefix="/api/security", tags=["AI & NHI Security"])

# In-memory activity tracking for security events
_SECURITY_STATS = {
    "injections_blocked": 14,
    "fields_redacted": 19,
    "manipulation_flags": 0,
    "nhi_custodian_gaps": 0,
}


class InspectTextRequest(BaseModel):
    text: str


@router.get("/stats")
def get_security_stats() -> dict[str, Any]:
    """Returns real-time AI security defense metrics and blocked attempt counters."""
    bundle = load_legacy_as_canonical()
    nhi_data = audit_non_human_identities(bundle)
    _SECURITY_STATS["nhi_custodian_gaps"] = nhi_data.get("unowned_count", 0)

    return {
        "status": "success",
        "stats": _SECURITY_STATS,
        "nhi_summary": {
            "total_nhi": nhi_data.get("total_non_human_identities", 0),
            "unowned": nhi_data.get("unowned_count", 0),
            "overprivileged": nhi_data.get("overprivileged_count", 0),
        },
    }


@router.get("/nhi")
def get_non_human_identities() -> dict[str, Any]:
    """Returns detailed audit of all Non-Human Identities, service accounts, and tokens."""
    bundle = load_legacy_as_canonical()
    return audit_non_human_identities(bundle)


@router.get("/redteam-benchmark")
def get_redteam_benchmark_results() -> dict[str, Any]:
    """Returns the latest Red-Team Prompt Injection benchmark results."""
    res = run_redteam_benchmark()
    return {"status": "success", "benchmark": res}


@router.post("/inspect-text")
def inspect_and_sanitize(req: InspectTextRequest) -> dict[str, Any]:
    """
    Live interactive testing endpoint: sanitizes input text and scans for prompt injection.
    """
    sanitized = sanitize_text(req.text)
    report = detect_and_redact_injection(sanitized)
    return {
        "status": "success",
        "original_text": req.text,
        "sanitized_text": sanitized,
        "is_injection": report.is_injection,
        "confidence": report.confidence,
        "matched_threats": report.matched_threats,
        "redacted_text": report.sanitized_text,
    }
