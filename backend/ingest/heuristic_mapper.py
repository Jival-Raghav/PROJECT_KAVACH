"""backend/ingest/heuristic_mapper.py
Heuristic Schema Mapper using synonym dictionaries, semantic types, RapidFuzz fuzzy matching,
and past correction learning from the mapping_feedback table.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import rapidfuzz.fuzz as fuzz
import yaml

from core.db import MappingFeedbackRecord, get_session
from ingest.profiler import ColumnProfile, TableProfile


class CandidateMapping(BaseModel):
    canonical_field: str
    source_column: str
    confidence: float
    transform: dict[str, Any] = Field(default_factory=lambda: {"op": "identity", "args": {}})
    rationale: str = ""


# ─── Load Canonical Synonyms ──────────────────────────────────────────────────

SYNONYMS_FILE = Path(__file__).parent / "synonyms.yaml"

def load_synonyms() -> dict[str, dict[str, list[str]]]:
    if not SYNONYMS_FILE.exists():
        return {}
    with open(SYNONYMS_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_SYNONYMS = load_synonyms()


# Canonical fields per table role
CANONICAL_FIELDS: dict[str, list[str]] = {
    "events": [
        "timestamp", "user_key", "action", "resource",
        "system", "resource_sensitivity", "success", "source_ip",
    ],
    "identities": [
        "identity_id", "employee_id", "full_name", "email",
        "department", "job_title", "manager_id", "employment_status",
        "hire_date", "termination_date", "location",
    ],
    "accounts": [
        "account_id", "system", "username", "email",
        "employee_id_hint", "account_type", "status",
        "last_login", "mfa_enabled", "privilege_level",
    ],
    "entitlements": [
        "account_id", "system", "entitlement", "privilege_weight",
    ],
    "systems": [
        "system", "sensitivity", "owner",
    ],
}


def compute_source_fingerprint(column_names: list[str]) -> str:
    """Deterministic SHA-256 fingerprint from sorted, lowercased column names."""
    norm = sorted(str(c).strip().lower() for c in column_names)
    text = "|".join(norm)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def get_past_feedback(fingerprint: str) -> dict[str, tuple[str, str, str]]:
    """Retrieve learned user corrections: source_column -> (target_field, role, transform_op)."""
    feedback_map = {}
    try:
        session = get_session()
        records = session.query(MappingFeedbackRecord).filter_by(fingerprint=fingerprint).all()
        for r in records:
            feedback_map[r.source_column.lower()] = (r.target_field, r.role, r.transform_op)
        session.close()
    except Exception:
        pass
    return feedback_map


def _recommend_transform(canonical_field: str, source_profile: ColumnProfile) -> dict[str, Any]:
    """Determine best declarative transform for a candidate mapping."""
    sem = source_profile.semantic_type
    c_lower = canonical_field.lower()

    if "timestamp" in c_lower or "date" in c_lower or "login" in c_lower:
        if sem == "epoch_s":
            return {"op": "epoch_s", "args": {}}
        elif sem == "epoch_ms":
            return {"op": "epoch_ms", "args": {}}
        else:
            return {"op": "parse_datetime", "args": {"format": "auto", "tz": "UTC"}}

    elif "user" in c_lower or "actor" in c_lower or "login" in c_lower or "email" in c_lower:
        # Check if AWS ARN
        top_str = " ".join(str(v) for v in source_profile.top_values if v)
        if "arn:aws:" in top_str or "arn" in source_profile.name.lower():
            return {"op": "arn_user", "args": {}}
        elif "@" in top_str and "email" not in c_lower:
            return {"op": "domain_strip", "args": {}}
        return {"op": "lower", "args": {}}

    elif "success" in c_lower or "mfa" in c_lower or "active" in c_lower:
        if sem == "boolean-like":
            return {"op": "bool_map", "args": {"true_values": ["true", "1", "yes", "y", "t", "success", "allowed"], "false_values": ["false", "0", "no", "n", "f", "failure", "denied"]}}

    elif "sensitivity" in c_lower:
        return {"op": "lower", "args": {}}

    return {"op": "identity", "args": {}}


def map_columns_heuristic(
    table_profile: TableProfile,
    target_role: str | None = None,
) -> list[CandidateMapping]:
    """Map source columns to canonical schema using synonyms, RapidFuzz,
    semantic types, and learned feedback.
    """
    role = target_role or table_profile.suggested_role
    if role not in CANONICAL_FIELDS:
        role = "events"

    canonical_list = CANONICAL_FIELDS.get(role, [])
    role_synonyms = _SYNONYMS.get(role, {})

    col_names = [c.name for c in table_profile.columns]
    fingerprint = compute_source_fingerprint(col_names)
    past_feedback = get_past_feedback(fingerprint)

    profile_by_col = {c.name: c for c in table_profile.columns}
    assigned_sources: set[str] = set()
    mappings: list[CandidateMapping] = []

    # 1. First, check past feedback from mapping_feedback table (Priority 1)
    for col_name in col_names:
        c_lower = col_name.lower()
        if c_lower in past_feedback:
            target_field, feedback_role, transform_op = past_feedback[c_lower]
            if target_field in canonical_list and col_name not in assigned_sources:
                mappings.append(CandidateMapping(
                    canonical_field=target_field,
                    source_column=col_name,
                    confidence=1.0,
                    transform={"op": transform_op, "args": {}},
                    rationale=f"Learned from past user correction for fingerprint {fingerprint}",
                ))
                assigned_sources.add(col_name)

    # 2. For each canonical field, find the best remaining matching source column
    mapped_canonicals = {m.canonical_field for m in mappings}

    for c_field in canonical_list:
        if c_field in mapped_canonicals:
            continue

        c_norm = c_field.lower().replace("_", "")
        synonyms = [s.lower() for s in role_synonyms.get(c_field, [])]

        best_col: str | None = None
        best_score = 0.0
        best_rationale = ""

        for col_name in col_names:
            if col_name in assigned_sources:
                continue

            prof = profile_by_col[col_name]
            col_lower = col_name.lower()
            col_norm = col_lower.replace("_", "").replace(".", "").replace("-", "")
            tail_lower = col_name.split(".")[-1].lower()
            tail_norm = tail_lower.replace("_", "").replace("-", "")

            # Exact match on full name or dot-notation tail
            if col_norm == c_norm or tail_norm == c_norm:
                score = 0.98
                if score > best_score:
                    best_score = score
                    best_col = col_name
                    best_rationale = f"Exact normalized column match with '{c_field}'"
                    continue

            # Exact match with a synonym
            if (
                col_lower in synonyms
                or tail_lower in synonyms
                or any(s.replace("_", "") in (col_norm, tail_norm) for s in synonyms)
            ):
                score = 0.95
                if c_field == "user_key":
                    if col_lower in ("actor.alternateid", "useridentity.arn"):
                        score = 0.99
                    elif "arn" in col_lower:
                        score = 0.97
                elif c_field == "account_id" and "arn" in col_lower:
                    score = 0.97
                if score > best_score:
                    best_score = score
                    best_col = col_name
                    best_rationale = f"Exact synonym match for '{c_field}'"
                    continue

            # RapidFuzz fuzzy match on column name vs canonical field and synonyms
            fuzz_scores = [
                fuzz.token_set_ratio(col_lower, c_field.lower()),
                fuzz.token_set_ratio(tail_lower, c_field.lower()),
            ]
            for s in synonyms:
                fuzz_scores.append(fuzz.token_set_ratio(col_lower, s))
                fuzz_scores.append(fuzz.token_set_ratio(tail_lower, s))
            max_fuzz = max(fuzz_scores) / 100.0

            # Semantic type bonus
            sem_bonus = 0.0
            if c_field == "timestamp" and prof.semantic_type in ("iso_datetime", "epoch_s", "epoch_ms", "date"):
                sem_bonus = 0.25
            elif c_field in ("email", "actor", "user_key") and prof.semantic_type == "email":
                sem_bonus = 0.20
            elif c_field in ("source_ip",) and prof.semantic_type == "ipv4/6":
                sem_bonus = 0.30
            elif c_field in ("employee_id", "identity_id") and prof.semantic_type == "employee_id-like":
                sem_bonus = 0.25
            elif c_field in ("success", "mfa_enabled") and prof.semantic_type == "boolean-like":
                sem_bonus = 0.25

            total_score = min(0.92, (0.75 * max_fuzz) + sem_bonus)

            if total_score > best_score:
                best_score = total_score
                best_col = col_name
                best_rationale = f"Fuzzy similarity ({int(max_fuzz*100)}%) and semantic compatibility"

        # If best match meets threshold (>= 0.55), accept heuristic candidate
        if best_col and best_score >= 0.55:
            prof = profile_by_col[best_col]
            transform = _recommend_transform(c_field, prof)
            mappings.append(CandidateMapping(
                canonical_field=c_field,
                source_column=best_col,
                confidence=round(best_score, 2),
                transform=transform,
                rationale=best_rationale,
            ))
            assigned_sources.add(best_col)

    return mappings
