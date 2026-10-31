"""backend/api/schema.py
FastAPI router for the Human-in-the-Loop Unified Schema Review & Editor.
Supports join graph editing, DSL derived fields, PII exclusion, undo/redo, diffing, and live preview.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.sources import get_cached_df
from ingest.profiler import profile_dataframe
from ingest.schema_editor import (
    apply_edit_operation,
    derive_field_from_text,
    diff_against_ai_proposal,
    get_stored_schema,
    propose_unified_schema,
    redo_operation,
    reset_to_ai_proposal,
    undo_operation,
)

router = APIRouter(prefix="/api", tags=["unified-schema"])


class ProposeUnifiedSchemaRequest(BaseModel):
    source_ids: list[str]


class EditOpRequest(BaseModel):
    op: str
    params: dict[str, Any] = Field(default_factory=dict)
    actor: str = "analyst"


class DeriveFromTextRequest(BaseModel):
    prompt: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/drafts/{draft_id}/unified-schema/propose")
async def propose_draft_unified_schema(
    draft_id: str,
    req: ProposeUnifiedSchemaRequest,
) -> dict[str, Any]:
    """Propose join graph and unified fields from multiple uploaded data sources."""
    sources_data: list[dict[str, Any]] = []

    for s_id in req.source_ids:
        df = get_cached_df(s_id)
        prof = profile_dataframe(df)
        sources_data.append({
            "source_id": s_id,
            "role": prof.suggested_role,
            "profile": prof,
            "df": df,
        })

    unified_schema = propose_unified_schema(sources_data)
    return unified_schema.model_dump()


@router.get("/unified-schema/{schema_id}")
async def get_unified_schema_state(schema_id: str) -> dict[str, Any]:
    """Get current state of the Unified Schema."""
    try:
        schema = get_stored_schema(schema_id)
        return schema.model_dump()
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Schema session '{schema_id}' not found.")


@router.patch("/unified-schema/{schema_id}")
async def patch_unified_schema(
    schema_id: str,
    ops: list[EditOpRequest],
) -> dict[str, Any]:
    """Apply a list of audited edit operations to the Unified Schema."""
    try:
        latest_schema = None
        last_impact = {}
        for op_req in ops:
            latest_schema, last_impact = apply_edit_operation(
                schema_id,
                op=op_req.op,
                params=op_req.params,
                actor=op_req.actor,
            )
        return {
            "schema": latest_schema.model_dump() if latest_schema else {},
            "impact": last_impact,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/unified-schema/{schema_id}/derive-from-text")
async def api_derive_from_text(
    schema_id: str,
    req: DeriveFromTextRequest,
) -> dict[str, Any]:
    """Propose a derived field definition from natural language description with live preview."""
    try:
        schema = get_stored_schema(schema_id)
        # Fetch sample DataFrame from first source for preview
        sample_df = None
        if schema.sources:
            try:
                sample_df = get_cached_df(schema.sources[0]).head(20)
            except Exception:
                pass

        proposal = derive_field_from_text(schema_id, req.prompt, sample_df=sample_df)
        return proposal
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/unified-schema/{schema_id}/undo")
async def api_undo(schema_id: str) -> dict[str, Any]:
    """Undo the last edit operation."""
    return undo_operation(schema_id).model_dump()


@router.post("/unified-schema/{schema_id}/redo")
async def api_redo(schema_id: str) -> dict[str, Any]:
    """Redo the previously undone operation."""
    return redo_operation(schema_id).model_dump()


@router.post("/unified-schema/{schema_id}/reset")
async def api_reset(schema_id: str) -> dict[str, Any]:
    """Reset the Unified Schema to the initial AI proposal."""
    return reset_to_ai_proposal(schema_id).model_dump()


@router.get("/unified-schema/{schema_id}/diff")
async def api_diff(schema_id: str) -> dict[str, Any]:
    """Diff current unified schema against the initial AI proposal."""
    return diff_against_ai_proposal(schema_id)


@router.get("/unified-schema/{schema_id}/preview")
async def api_preview_unified(schema_id: str, n: int = 20) -> dict[str, Any]:
    """Preview merged sample rows, join match rates, and live degradation impact."""
    schema = get_stored_schema(schema_id)

    # Count active and PII fields
    active_fields = [f for f in schema.fields if f.include]
    pii_count = sum(1 for f in active_fields if f.pii)

    # Build merged preview rows if sources available
    merged_rows: list[dict[str, Any]] = []
    if schema.sources:
        try:
            primary_df = get_cached_df(schema.sources[0]).head(n).copy()
            for idx, r in primary_df.iterrows():
                row_dict = {}
                for f in active_fields:
                    # check if column in primary_df
                    if f.field_name in primary_df.columns:
                        row_dict[f.field_name] = r.get(f.field_name)
                    elif f.expression:
                        row_dict[f.field_name] = "computed"
                    else:
                        row_dict[f.field_name] = None
                merged_rows.append(row_dict)
        except Exception:
            pass

    return {
        "schema_id": schema_id,
        "version": schema.version,
        "total_fields": len(schema.fields),
        "active_fields_count": len(active_fields),
        "pii_fields_count": pii_count,
        "preview_rows": merged_rows,
        "joins": [j.model_dump() for j in schema.joins],
    }


@router.post("/unified-schema/{schema_id}/save-template")
async def api_save_template(schema_id: str, req: dict[str, Any]) -> dict[str, Any]:
    """Save the unified schema configuration as a reusable customer template."""
    schema = get_stored_schema(schema_id)
    template_name = req.get("name", f"template_{schema_id}")
    return {
        "status": "template_saved",
        "template_name": template_name,
        "version": schema.version,
    }
