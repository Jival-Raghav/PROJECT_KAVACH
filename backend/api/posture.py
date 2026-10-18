"""
backend/api/posture.py — FastAPI router for Enterprise Posture & Continuous Compliance.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Query, Response

from ingest.legacy_adapter import load_legacy_as_canonical
from posture.score import calculate_identity_hygiene_score
from posture.compliance import evaluate_compliance
from posture.report import (
    generate_audit_pack_pdf,
    generate_audit_pack_json,
    generate_audit_pack_csv,
)

router = APIRouter(prefix="/api/posture", tags=["Posture & Compliance"])


@router.get("/score")
def get_posture_score() -> dict[str, Any]:
    """Returns the Identity Hygiene Score, subscores, drivers, and weights."""
    bundle = load_legacy_as_canonical()
    score_data = calculate_identity_hygiene_score(bundle)
    return {"status": "success", "data": score_data}


@router.get("/controls")
def get_compliance_controls() -> dict[str, Any]:
    """Evaluates and returns status across NIST, ISO 27001, and DPDP Act."""
    bundle = load_legacy_as_canonical()
    compliance_data = evaluate_compliance(bundle)
    return compliance_data


@router.get("/insurer-summary")
def get_insurer_summary() -> dict[str, Any]:
    """Returns the illustrative insurer exposure index and risk multipliers."""
    bundle = load_legacy_as_canonical()
    score_data = calculate_identity_hygiene_score(bundle)
    return {
        "status": "success",
        "insurer_exposure": score_data.get("insurer_exposure", {}),
        "hygiene_score": score_data.get("identity_hygiene_score"),
        "grade": score_data.get("grade"),
    }


@router.get("/export")
def export_audit_pack(
    format: str = Query("pdf", pattern="^(pdf|json|csv)$"),
):
    """Generates and downloads formal compliance audit pack in PDF, JSON, or CSV."""
    bundle = load_legacy_as_canonical()
    hygiene = calculate_identity_hygiene_score(bundle)
    compliance = evaluate_compliance(bundle, hygiene)

    if format == "pdf":
        pdf_bytes = generate_audit_pack_pdf(bundle, hygiene, compliance)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Kavach_Audit_Pack.pdf"},
        )
    elif format == "json":
        json_str = generate_audit_pack_json(bundle, hygiene, compliance)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=Kavach_Audit_Pack.json"},
        )
    else:
        csv_str = generate_audit_pack_csv(compliance)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=Kavach_Compliance_Evidence.csv"},
        )
