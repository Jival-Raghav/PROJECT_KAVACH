"""backend/api/investigate.py
FastAPI router for Phase 4: Evidence-Grounded Devil's Advocate Co-Pilot.

Endpoints:
- POST /api/investigate/{user_id}: Trigger adversarial investigation on an accused user.
- GET  /api/investigate/{user_id}/case: Retrieve complete case dossier.
- GET  /api/investigate/cases: List all investigated case summaries.
- GET  /api/investigate/tools: List allowed verification tools and their parameter schemas.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from ingest.legacy_adapter import load_legacy_bundle
from llm.investigate import get_case_dossier, investigate_user, list_investigated_cases
from llm.tools import TOOL_METADATA
from pydantic import BaseModel

router = APIRouter(prefix="/api/investigate", tags=["Remediation Co-Pilot"])


class TriggerInvestigationPayload(BaseModel):
    run_id: str = "default"
    use_llm: bool = True


@router.post("/{user_id}")
def trigger_investigation(
    user_id: str,
    payload: TriggerInvestigationPayload | None = None,
) -> dict[str, Any]:
    """Execute full 3-pass investigative review (Prosecutor -> DA -> Adjudicator)."""
    try:
        run_id = payload.run_id if payload else "default"
        use_llm = payload.use_llm if payload else True

        bundle = load_legacy_bundle(run_id=run_id)
        verdict = investigate_user(
            bundle=bundle,
            user_id=user_id,
            use_llm=use_llm,
        )
        return {
            "status": "success",
            "case": verdict.model_dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {e}") from e


@router.get("/{user_id}/case")
def get_case(user_id: str, run_id: str = Query("default")) -> dict[str, Any]:
    """Retrieve existing case report for a user, running on-demand if not already generated."""
    case = get_case_dossier(user_id)
    if not case:
        try:
            bundle = load_legacy_bundle(run_id=run_id)
            case = investigate_user(bundle=bundle, user_id=user_id, use_llm=False)
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Case for user '{user_id}' not found: {e}") from e

    return {
        "status": "success",
        "case": case.model_dump(),
    }


@router.get("/cases")
def list_cases() -> dict[str, Any]:
    """List summary records of all investigated cases in current session."""
    cases = list_investigated_cases()
    return {
        "status": "success",
        "total_cases": len(cases),
        "cases": cases,
    }


@router.get("/tools")
def list_available_tools() -> dict[str, Any]:
    """List allowed read-only evidence verification tools with schemas."""
    return {
        "status": "success",
        "total_tools": len(TOOL_METADATA),
        "tools": TOOL_METADATA,
    }
