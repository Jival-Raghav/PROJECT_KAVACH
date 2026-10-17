"""backend/ingest/schema_editor.py
Stateful engine for the Human-in-the-Loop Unified Schema Review & Editor.
Manages join graph generation, field promotion, sandboxed DSL derivation,
dependency cascade tracking, undo/redo, diffing, and "describe in words" AI generation.
"""
from __future__ import annotations

import copy
import uuid
from typing import Any

import pandas as pd

from ingest.dsl import DSLExpression
from ingest.profiler import TableProfile
from ingest.unified_schema import (
    EditOp,
    JoinEdge,
    OriginEnum,
    ProvenanceEnum,
    RoleEnum,
    UnifiedField,
    UnifiedSchema,
)
from ingest.validate import evaluate_degradation_matrix


# In-memory store for active editing sessions (cached by schema_id)
_SCHEMA_STORE: dict[str, UnifiedSchema] = {}
_UNDO_STORE: dict[str, list[UnifiedSchema]] = {}
_REDO_STORE: dict[str, list[UnifiedSchema]] = {}


def get_stored_schema(schema_id: str) -> UnifiedSchema:
    if schema_id not in _SCHEMA_STORE:
        raise KeyError(f"Unified schema session '{schema_id}' not found.")
    return _SCHEMA_STORE[schema_id]


def _save_schema_state(schema_id: str, new_state: UnifiedSchema) -> None:
    curr = _SCHEMA_STORE.get(schema_id)
    if curr:
        _UNDO_STORE.setdefault(schema_id, []).append(copy.deepcopy(curr))
    _SCHEMA_STORE[schema_id] = new_state
    _REDO_STORE[schema_id] = []  # Clear redo stack on new operation


# ─── Propose Initial Unified Schema ───────────────────────────────────────────

def propose_unified_schema(
    sources: list[dict[str, Any]],  # list of {source_id, role, profile: TableProfile, df: DataFrame}
) -> UnifiedSchema:
    """Analyze multi-source datasets, generate join graph candidates, and propose unified fields."""
    schema_id = f"us_{uuid.uuid4().hex[:12]}"
    source_ids = [s["source_id"] for s in sources]
    joins: list[JoinEdge] = []
    fields: list[UnifiedField] = []

    events_source = next((s for s in sources if s.get("role") == "events"), None)
    identities_source = next((s for s in sources if s.get("role") == "identities"), None)

    # 1. Propose Joins
    if events_source and identities_source:
        ev_df = events_source.get("df")
        id_df = identities_source.get("df")
        match_rate = 0.90
        unmatched = []

        # Find best join key
        ev_keys = [c for c in ev_df.columns if any(k in c.lower() for k in ("user", "actor", "login", "emp"))] if ev_df is not None else []
        id_keys = [c for c in id_df.columns if any(k in c.lower() for k in ("id", "emp", "mail", "user"))] if id_df is not None else []

        left_k = [ev_keys[0]] if ev_keys else ["user_key"]
        right_k = [id_keys[0]] if id_keys else ["employee_id"]

        if ev_df is not None and id_df is not None and left_k[0] in ev_df.columns and right_k[0] in id_df.columns:
            sample_ev = set(ev_df[left_k[0]].dropna().astype(str).str.lower().head(100))
            target_ids = set(id_df[right_k[0]].dropna().astype(str).str.lower())
            if sample_ev:
                matched = len(sample_ev.intersection(target_ids))
                match_rate = round(float(matched / len(sample_ev)), 2)
                unmatched = list(sample_ev - target_ids)[:5]

        joins.append(JoinEdge(
            id=f"join_{uuid.uuid4().hex[:8]}",
            left_source=events_source["source_id"],
            right_source=identities_source["source_id"],
            left_keys=left_k,
            right_keys=right_k,
            join_type="left",
            match_rate=match_rate,
            unmatched_samples=unmatched,
            confidence=0.92,
        ))

    # 2. Propose Unified Fields
    seen_field_names: set[str] = set()

    for src in sources:
        s_id = src["source_id"]
        profile: TableProfile | None = src.get("profile")

        if not profile:
            continue

        for col in profile.columns:
            raw_name = col.name

            # Deduce role and PII flag
            field_role = RoleEnum.FEATURE.value
            is_pii = col.semantic_type in ("email", "ipv4/6") or any(k in raw_name.lower() for k in ("email", "mail", "name", "phone", "ssn", "ip"))

            if any(k in raw_name.lower() for k in ("time", "ts", "date", "created")):
                field_role = RoleEnum.TIMESTAMP.value
            elif any(k in raw_name.lower() for k in ("user", "actor", "login", "principal")):
                field_role = RoleEnum.ACTOR.value
            elif any(k in raw_name.lower() for k in ("action", "event_name", "activity", "verb")):
                field_role = RoleEnum.ACTION.value
            elif any(k in raw_name.lower() for k in ("resource", "object", "target", "uri")):
                field_role = RoleEnum.RESOURCE.value
            elif any(k in raw_name.lower() for k in ("sensitivity", "tier", "criticality")):
                field_role = RoleEnum.SENSITIVITY.value
            elif any(k in raw_name.lower() for k in ("dept", "department", "team", "division", "job_title", "title")):
                field_role = RoleEnum.PEER_GROUP.value
            elif any(k in raw_name.lower() for k in ("privilege", "admin", "role", "elevation")):
                field_role = RoleEnum.PRIVILEGE.value
            elif any(k in raw_name.lower() for k in ("id", "emp_id", "uuid")):
                field_role = RoleEnum.IDENTIFIER.value

            unique_name = raw_name
            if unique_name in seen_field_names:
                unique_name = f"{s_id}_{raw_name}"
            seen_field_names.add(unique_name)

            fields.append(UnifiedField(
                field_name=unique_name,
                origin=OriginEnum.CANONICAL.value,
                source_refs=[f"{s_id}.{raw_name}"],
                dtype=col.dtype,
                role=field_role,
                include=True,
                pii=is_pii,
                description=f"Auto-mapped from {s_id}.{raw_name} (type: {col.semantic_type})",
                confidence=0.92,
                provenance=ProvenanceEnum.AI.value,
            ))

    proposal = UnifiedSchema(
        id=schema_id,
        version=1,
        sources=source_ids,
        joins=joins,
        fields=fields,
        edit_log=[],
    )
    proposal.ai_proposal_json = proposal.model_dump_json()

    _SCHEMA_STORE[schema_id] = proposal
    return proposal


# ─── Dependency Graph & Cascade Safety ────────────────────────────────────────

def get_field_dependencies(schema: UnifiedSchema) -> dict[str, list[str]]:
    """Build a mapping of field_name -> list of derived fields that depend on it."""
    dep_map: dict[str, list[str]] = {f.field_name: [] for f in schema.fields}

    for f in schema.fields:
        if f.origin == OriginEnum.DERIVED.value and f.expression:
            try:
                expr = DSLExpression(f.expression)
                for ref in expr.referenced_fields:
                    if ref in dep_map:
                        dep_map[ref].append(f.field_name)
            except Exception:
                pass
    return dep_map


def check_cascade_impact(schema: UnifiedSchema, field_name: str) -> list[str]:
    """Returns list of dependent field names that will break if field_name is excluded."""
    dep_map = get_field_dependencies(schema)
    dependents: list[str] = []

    def visit(target: str):
        for child in dep_map.get(target, []):
            if child not in dependents:
                dependents.append(child)
                visit(child)

    visit(field_name)
    return dependents


# ─── Apply Edit Operations ───────────────────────────────────────────────────

def apply_edit_operation(
    schema_id: str,
    op: str,
    params: dict[str, Any],
    actor: str = "analyst",
) -> tuple[UnifiedSchema, dict[str, Any]]:
    """Apply an audited mutation to the UnifiedSchema and return the updated state with impact."""
    schema = get_stored_schema(schema_id)
    next_schema = copy.deepcopy(schema)
    next_schema.version += 1
    impact_info: dict[str, Any] = {}

    edit_entry = EditOp(op=op, params=params, actor=actor)

    if op == "remove_field":
        fname = params["field_name"]
        dependents = check_cascade_impact(next_schema, fname)
        cascade = params.get("cascade", False)

        for f in next_schema.fields:
            if f.field_name == fname:
                f.include = False
                f.provenance = ProvenanceEnum.HUMAN_REMOVED.value
            elif cascade and f.field_name in dependents:
                f.include = False
                f.provenance = ProvenanceEnum.HUMAN_REMOVED.value

        impact_info["affected_dependents"] = dependents

    elif op == "include_field":
        fname = params["field_name"]
        for f in next_schema.fields:
            if f.field_name == fname:
                f.include = True
                f.provenance = ProvenanceEnum.HUMAN_EDITED.value

    elif op == "exclude_all_pii":
        count = 0
        for f in next_schema.fields:
            if f.pii and f.include:
                f.include = False
                f.provenance = ProvenanceEnum.HUMAN_REMOVED.value
                count += 1
        impact_info["pii_fields_excluded"] = count

    elif op == "add_passthrough":
        fname = params["field_name"]
        source_ref = params.get("source_ref", "")
        dtype = params.get("dtype", "string")
        role = params.get("role", RoleEnum.FEATURE.value)

        # Check duplicate
        if any(f.field_name == fname for f in next_schema.fields):
            raise ValueError(f"Field with name '{fname}' already exists in Unified Schema.")

        next_schema.fields.append(UnifiedField(
            field_name=fname,
            origin=OriginEnum.PASSTHROUGH.value,
            source_refs=[source_ref] if source_ref else [],
            dtype=dtype,
            role=role,
            include=True,
            pii=False,
            description=params.get("description", "Human promoted custom column"),
            confidence=1.0,
            provenance=ProvenanceEnum.HUMAN_ADDED.value,
        ))

    elif op == "add_derived":
        fname = params["field_name"]
        expr_str = params["expression"]
        role = params.get("role", RoleEnum.FEATURE.value)
        dtype = params.get("dtype", "float")

        # Validate with sandboxed DSL
        expr = DSLExpression(expr_str)

        if any(f.field_name == fname for f in next_schema.fields):
            raise ValueError(f"Field with name '{fname}' already exists.")

        next_schema.fields.append(UnifiedField(
            field_name=fname,
            origin=OriginEnum.DERIVED.value,
            source_refs=[f"derived:{ref}" for ref in expr.referenced_fields],
            dtype=dtype,
            role=role,
            include=True,
            pii=False,
            description=params.get("description", f"DSL: {expr_str}"),
            confidence=1.0,
            provenance=ProvenanceEnum.HUMAN_ADDED.value,
            expression=expr_str,
        ))

    elif op == "rename_field":
        old_name = params["old_name"]
        new_name = params["new_name"]

        target = next((f for f in next_schema.fields if f.field_name == old_name), None)
        if not target:
            raise KeyError(f"Field '{old_name}' not found.")
        target.field_name = new_name
        target.provenance = ProvenanceEnum.HUMAN_EDITED.value

        # Update dependent expressions
        for f in next_schema.fields:
            if f.origin == OriginEnum.DERIVED.value and f.expression:
                f.expression = f.expression.replace(f"${{{old_name}}}", f"${{{new_name}}}")

    elif op == "set_role":
        fname = params["field_name"]
        new_role = params["role"]
        for f in next_schema.fields:
            if f.field_name == fname:
                f.role = new_role
                f.provenance = ProvenanceEnum.HUMAN_EDITED.value

    elif op == "set_pii":
        fname = params["field_name"]
        val = bool(params["pii"])
        for f in next_schema.fields:
            if f.field_name == fname:
                f.pii = val
                f.provenance = ProvenanceEnum.HUMAN_EDITED.value

    elif op == "edit_join":
        jid = params["join_id"]
        for j in next_schema.joins:
            if j.id == jid:
                if "left_keys" in params:
                    j.left_keys = params["left_keys"]
                if "right_keys" in params:
                    j.right_keys = params["right_keys"]
                if "join_type" in params:
                    j.join_type = params["join_type"]

    elif op == "add_join":
        next_schema.joins.append(JoinEdge(
            id=f"join_{uuid.uuid4().hex[:8]}",
            left_source=params["left_source"],
            right_source=params["right_source"],
            left_keys=params["left_keys"],
            right_keys=params["right_keys"],
            join_type=params.get("join_type", "left"),
            match_rate=1.0,
            confidence=1.0,
        ))

    elif op == "remove_join":
        jid = params["join_id"]
        next_schema.joins = [j for j in next_schema.joins if j.id != jid]

    else:
        raise ValueError(f"Unknown edit operation: '{op}'")

    next_schema.edit_log.append(edit_entry)
    _save_schema_state(schema_id, next_schema)

    # Recompute degradation matrix impact
    active_fields = [f.field_name for f in next_schema.fields if f.include]
    degradation = evaluate_degradation_matrix(
        ["events", "identities"],
        {"events": active_fields, "identities": active_fields},
    )
    impact_info["degradation_matrix"] = [d.model_dump() for d in degradation]

    return next_schema, impact_info


# ─── Undo, Redo, Reset, Diff ─────────────────────────────────────────────────

def undo_operation(schema_id: str) -> UnifiedSchema:
    undo_stack = _UNDO_STORE.get(schema_id, [])
    if not undo_stack:
        return get_stored_schema(schema_id)

    curr = _SCHEMA_STORE[schema_id]
    _REDO_STORE.setdefault(schema_id, []).append(copy.deepcopy(curr))

    prev_state = undo_stack.pop()
    _SCHEMA_STORE[schema_id] = prev_state
    return prev_state


def redo_operation(schema_id: str) -> UnifiedSchema:
    redo_stack = _REDO_STORE.get(schema_id, [])
    if not redo_stack:
        return get_stored_schema(schema_id)

    curr = _SCHEMA_STORE[schema_id]
    _UNDO_STORE.setdefault(schema_id, []).append(copy.deepcopy(curr))

    next_state = redo_stack.pop()
    _SCHEMA_STORE[schema_id] = next_state
    return next_state


def reset_to_ai_proposal(schema_id: str) -> UnifiedSchema:
    schema = get_stored_schema(schema_id)
    if not schema.ai_proposal_json:
        return schema

    curr = _SCHEMA_STORE[schema_id]
    _UNDO_STORE.setdefault(schema_id, []).append(copy.deepcopy(curr))

    original = UnifiedSchema.model_validate_json(schema.ai_proposal_json)
    original.edit_log = []
    _SCHEMA_STORE[schema_id] = original
    _REDO_STORE[schema_id] = []
    return original


def diff_against_ai_proposal(schema_id: str) -> dict[str, Any]:
    schema = get_stored_schema(schema_id)
    if not schema.ai_proposal_json:
        return {"added_fields": [], "removed_fields": [], "modified_fields": []}

    original = UnifiedSchema.model_validate_json(schema.ai_proposal_json)
    orig_map = {f.field_name: f for f in original.fields}
    curr_map = {f.field_name: f for f in schema.fields}

    added = [f.model_dump() for name, f in curr_map.items() if name not in orig_map]
    removed = [f.model_dump() for name, f in curr_map.items() if not f.include and orig_map.get(name, UnifiedField(field_name=name)).include]
    modified = []

    for name, f in curr_map.items():
        if name in orig_map and f.include:
            orig_f = orig_map[name]
            changes = {}
            if orig_f.role != f.role:
                changes["role"] = {"old": orig_f.role, "new": f.role}
            if orig_f.pii != f.pii:
                changes["pii"] = {"old": orig_f.pii, "new": f.pii}
            if changes:
                modified.append({"field_name": name, "changes": changes})

    return {
        "added_fields": added,
        "removed_fields": removed,
        "modified_fields": modified,
    }


# ─── Describe-in-Words Derived Field Proposal ─────────────────────────────────

def derive_field_from_text(
    schema_id: str,
    prompt: str,
    sample_df: pd.DataFrame | None = None,
) -> dict[str, Any]:
    """Use AI or deterministic natural language parsing to propose a DSL expression for a derived field."""
    schema = get_stored_schema(schema_id)
    field_names = [f.field_name for f in schema.fields if f.include]

    p_lower = prompt.lower()
    proposed_name = "custom_metric"
    proposed_expr = ""
    proposed_role = RoleEnum.FEATURE.value
    description = prompt

    # Heuristic template patterns for common natural language security expressions
    if "weekend" in p_lower or "saturday" in p_lower or "sunday" in p_lower:
        ts_field = next((f for f in field_names if "time" in f.lower() or "date" in f.lower()), "timestamp")
        proposed_name = "is_weekend_activity"
        proposed_expr = f"is_weekend(${{{ts_field}}})"
        description = f"True if activity on Saturday or Sunday based on {ts_field}"

    elif "outside" in p_lower and ("hour" in p_lower or "business" in p_lower):
        ts_field = next((f for f in field_names if "time" in f.lower() or "date" in f.lower()), "timestamp")
        proposed_name = "is_after_hours"
        proposed_expr = f"if(hour(${{{ts_field}}}) < 9 or hour(${{{ts_field}}}) >= 18, True, False)"
        description = f"True if activity occurred outside 09:00 - 18:00 ({ts_field})"

    elif "days since" in p_lower or "inactive" in p_lower or "last login" in p_lower:
        d1 = next((f for f in field_names if "time" in f.lower() or "event" in f.lower()), "timestamp")
        d2 = next((f for f in field_names if "login" in f.lower() or "hire" in f.lower()), "last_login")
        proposed_name = "days_since_last_login"
        proposed_expr = f"date_diff_days(${{{d1}}}, ${{{d2}}})"
        description = f"Days elapsed between {d1} and {d2}"

    elif "ratio" in p_lower or "division" in p_lower:
        proposed_name = "activity_ratio"
        proposed_expr = "ratio(1, 10)"
        description = "Ratio metric"

    else:
        # Generic fallback
        first_num = next((f for f in field_names if "count" in f.lower() or "score" in f.lower()), field_names[0] if field_names else "val")
        proposed_name = "derived_" + "".join(c for c in p_lower if c.isalnum())[:16]
        proposed_expr = f"round(coalesce(${{{first_num}}}, 0), 2)"

    # Validate expression using sandboxed DSL parser
    expr_obj = DSLExpression(proposed_expr)

    # Preview against sample DataFrame if provided
    preview_vals: list[Any] = []
    if sample_df is not None and not sample_df.empty:
        try:
            res_series = expr_obj.evaluate_df(sample_df.head(20))
            preview_vals = res_series.tolist()
        except Exception:
            pass

    return {
        "field_name": proposed_name,
        "expression": proposed_expr,
        "role": proposed_role,
        "dtype": "float" if "date_diff" in proposed_expr or "ratio" in proposed_expr else "boolean",
        "description": description,
        "referenced_fields": expr_obj.referenced_fields,
        "preview_values": preview_vals[:20],
    }
