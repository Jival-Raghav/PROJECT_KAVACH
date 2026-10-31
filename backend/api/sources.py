"""backend/api/sources.py
FastAPI router for Data Sources, Profiling, Mapping Proposals, and Validation.
Integrates user correction learning into the mapping_feedback database table.
"""
from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from core.db import (
    MappingFeedbackRecord,
    MappingProfileRecord,
    RunRecord,
    SourceRecord,
    get_session,
)
from ingest.heuristic_mapper import compute_source_fingerprint
from ingest.llm_mapper import propose_mapping
from ingest.profiler import profile_dataframe
from ingest.readers import read_file_to_df, read_sql_to_df
from ingest.validate import validate_source_mapping

router = APIRouter(prefix="/api", tags=["sources"])

UPLOAD_DIR = Path("data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# In-memory DataFrame cache: source_id -> DataFrame
_DATAFRAME_CACHE: dict[str, pd.DataFrame] = {}


def get_cached_df(source_id: str) -> pd.DataFrame:
    if source_id in _DATAFRAME_CACHE:
        return _DATAFRAME_CACHE[source_id]

    session = get_session()
    rec = session.query(SourceRecord).filter_by(source_id=source_id).first()
    session.close()

    if not rec:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found.")

    filepath = UPLOAD_DIR / f"{source_id}_{rec.filename}"
    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Source file for '{source_id}' not found on disk.")

    df = read_file_to_df(filepath)
    _DATAFRAME_CACHE[source_id] = df
    return df


class SQLConfigRequest(BaseModel):
    connection_string: str
    table_name: str | None = None
    query: str | None = None
    row_cap: int = 1000


class ProposeMappingRequest(BaseModel):
    target_role: str | None = None
    use_llm: bool = True


class SaveMappingProfileRequest(BaseModel):
    source_id: str
    role: str = "events"
    mappings: list[dict[str, Any]]
    created_by: str = "analyst"
    notes: str = ""


class CreateRunRequest(BaseModel):
    source_ids: list[str]
    profile_ids: list[str]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/sources")
async def upload_source(
    file: UploadFile | None = File(None),
    sql_config: str | None = Form(None),
) -> dict[str, Any]:
    """Upload a tabular file (CSV, TSV, JSON, Parquet) or register a read-only SQL connection."""
    source_id = f"src_{uuid.uuid4().hex[:10]}"

    if file:
        filename = file.filename or "unknown.csv"
        file_path = UPLOAD_DIR / f"{source_id}_{filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        df = read_file_to_df(file_path)
        ext = Path(filename).suffix.lower().lstrip(".")
        file_type = ext if ext in ("csv", "tsv", "json", "jsonl", "parquet") else "csv"

    elif sql_config:
        try:
            cfg_dict = json.loads(sql_config)
            conn_str = cfg_dict["connection_string"]
            t_name = cfg_dict.get("table_name")
            q = cfg_dict.get("query")
            cap = int(cfg_dict.get("row_cap", 1000))
            df = read_sql_to_df(conn_str, table_name=t_name, query=q, row_cap=cap)
            filename = f"sql_{t_name or 'query'}"
            file_type = "sql"
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read from SQL source: {e}")
    else:
        raise HTTPException(status_code=400, detail="Either file upload or sql_config is required.")

    _DATAFRAME_CACHE[source_id] = df
    table_profile = profile_dataframe(df)

    # Persist in SQLite
    session = get_session()
    rec = SourceRecord(
        source_id=source_id,
        filename=filename,
        file_type=file_type,
        row_count=len(df),
        profile_json=table_profile.model_dump_json(),
    )
    session.add(rec)
    session.commit()
    session.close()

    return {
        "source_id": source_id,
        "filename": filename,
        "file_type": file_type,
        "row_count": len(df),
        "suggested_role": table_profile.suggested_role,
        "role_confidence": table_profile.role_confidence,
        "profile": table_profile.model_dump(),
    }


@router.get("/sources/{source_id}/profile")
async def get_source_profile(source_id: str) -> dict[str, Any]:
    """Retrieve statistical and semantic column profile for a registered source."""
    session = get_session()
    rec = session.query(SourceRecord).filter_by(source_id=source_id).first()
    session.close()
    if not rec:
        raise HTTPException(status_code=404, detail="Source not found.")

    return json.loads(rec.profile_json or "{}")


@router.post("/sources/{source_id}/propose-mapping")
async def propose_source_mapping(
    source_id: str,
    req: ProposeMappingRequest,
) -> dict[str, Any]:
    """Generate heuristic + LLM mapping proposal with confidence scores."""
    df = get_cached_df(source_id)
    profile = profile_dataframe(df)
    proposal = propose_mapping(profile, target_role=req.target_role, use_llm=req.use_llm)
    return proposal.model_dump()


@router.put("/mappings/{profile_id}")
async def save_mapping_profile(
    profile_id: str,
    req: SaveMappingProfileRequest,
) -> dict[str, Any]:
    """Save user-approved mapping profile and record feedback in mapping_feedback table for future learning."""
    df = get_cached_df(req.source_id)
    fingerprint = compute_source_fingerprint(list(df.columns))

    session = get_session()
    existing = session.query(MappingProfileRecord).filter_by(profile_id=profile_id).first()
    if existing:
        existing.role = req.role
        existing.mappings_json = json.dumps(req.mappings)
        existing.notes = req.notes
    else:
        new_prof = MappingProfileRecord(
            profile_id=profile_id,
            source_fingerprint=fingerprint,
            role=req.role,
            mappings_json=json.dumps(req.mappings),
            created_by=req.created_by,
            notes=req.notes,
        )
        session.add(new_prof)

    # Record user corrections in mapping_feedback table for persistent learning
    for m in req.mappings:
        src_col = m.get("source_column")
        tgt_fld = m.get("canonical_field")
        tf_op = m.get("transform", {}).get("op", "identity")
        if src_col and tgt_fld:
            fb = MappingFeedbackRecord(
                fingerprint=fingerprint,
                source_column=src_col,
                target_field=tgt_fld,
                role=req.role,
                transform_op=tf_op,
            )
            session.add(fb)

    session.commit()
    session.close()

    return {"status": "saved", "profile_id": profile_id, "fingerprint": fingerprint}


@router.post("/mappings/{profile_id}/preview")
async def preview_mapping(
    profile_id: str,
    req: dict[str, Any],  # {"source_id": "...", "role": "...", "mappings": [...]}
) -> dict[str, Any]:
    """Preview 20 normalized rows with parse error rates and degradation matrix."""
    source_id = req["source_id"]
    role = req.get("role", "events")
    mappings = req.get("mappings", [])

    df = get_cached_df(source_id)
    val_report = validate_source_mapping(df, role, mappings)

    # Build 20 preview rows
    sample_df = df.head(20).copy()
    transformed_rows: list[dict[str, Any]] = []

    for idx, row in sample_df.iterrows():
        out_row: dict[str, Any] = {}
        for m in mappings:
            c_field = m["canonical_field"]
            s_col = m["source_column"]
            tf = m.get("transform", {"op": "identity"})
            val = row.get(s_col)
            try:
                from ingest.transforms import apply_transform
                out_row[c_field] = apply_transform(val, tf)
            except Exception:
                out_row[c_field] = None
        transformed_rows.append(out_row)

    return {
        "preview_rows": transformed_rows,
        "validation": val_report.model_dump(),
    }


@router.post("/runs")
async def create_run(req: CreateRunRequest) -> dict[str, Any]:
    """Start an end-to-end pipeline run from selected sources and mapping profiles."""
    run_id = f"run_{uuid.uuid4().hex[:12]}"

    session = get_session()
    run_rec = RunRecord(
        run_id=run_id,
        status="running",
        source_hash=",".join(req.source_ids),
        mapping_profile_id=",".join(req.profile_ids),
        summary_json="{}",
    )
    session.add(run_rec)
    session.commit()
    session.close()

    return {"run_id": run_id, "status": "running"}


@router.get("/runs/{run_id}/validation")
async def get_run_validation(run_id: str) -> dict[str, Any]:
    """Get validation and degradation matrix for a run."""
    session = get_session()
    run = session.query(RunRecord).filter_by(run_id=run_id).first()
    session.close()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found.")

    return {
        "run_id": run_id,
        "status": run.status,
        "summary": run.to_dict()["summary"],
    }
