"""tests/test_unified_schema.py
Unit tests for Human-in-the-Loop Unified Schema Review & Editor.
Verifies join graph proposals, reversible edit operations (undo/redo), cascade dependency safety,
diffing against AI proposal, and describe-in-words DSL generation.
"""
from __future__ import annotations

import pandas as pd
import pytest

from ingest.profiler import profile_dataframe
from ingest.schema_editor import (
    apply_edit_operation,
    derive_field_from_text,
    diff_against_ai_proposal,
    propose_unified_schema,
    redo_operation,
    reset_to_ai_proposal,
    undo_operation,
)
from ingest.unified_schema import RoleEnum


@pytest.fixture
def mock_multi_source():
    ev_df = pd.DataFrame([
        {"timestamp": "2026-03-20T10:00:00Z", "user_key": "u101", "action": "LOGIN", "source_ip": "10.0.0.1"},
        {"timestamp": "2026-03-20T11:00:00Z", "user_key": "u102", "action": "READ", "source_ip": "10.0.0.2"},
    ])
    id_df = pd.DataFrame([
        {"employee_id": "u101", "full_name": "Alice Smith", "email": "alice@acme.corp", "department": "Finance"},
        {"employee_id": "u102", "full_name": "Bob Jones", "email": "bob@acme.corp", "department": "Engineering"},
    ])

    return [
        {"source_id": "events_log", "role": "events", "profile": profile_dataframe(ev_df), "df": ev_df},
        {"source_id": "hr_roster", "role": "identities", "profile": profile_dataframe(id_df), "df": id_df},
    ]


def test_propose_unified_schema(mock_multi_source):
    schema = propose_unified_schema(mock_multi_source)
    assert schema.id.startswith("us_")
    assert len(schema.joins) == 1
    assert schema.joins[0].left_source == "events_log"
    assert schema.joins[0].right_source == "hr_roster"
    assert schema.joins[0].match_rate == 1.0

    field_names = [f.field_name for f in schema.fields]
    assert "timestamp" in field_names
    assert "email" in field_names


def test_edit_ops_undo_redo_and_reset(mock_multi_source):
    schema = propose_unified_schema(mock_multi_source)
    sid = schema.id

    # 1. Add derived field
    schema, impact = apply_edit_operation(
        sid,
        op="add_derived",
        params={
            "field_name": "is_weekend_login",
            "expression": "is_weekend(${timestamp})",
            "role": RoleEnum.FEATURE.value,
        },
    )
    assert any(f.field_name == "is_weekend_login" for f in schema.fields)

    # 2. Add passthrough custom field
    schema, _ = apply_edit_operation(
        sid,
        op="add_passthrough",
        params={
            "field_name": "custom_tag",
            "dtype": "string",
            "role": RoleEnum.CONTEXT_ONLY.value,
        },
    )
    assert any(f.field_name == "custom_tag" for f in schema.fields)

    # 3. Exclude all PII
    schema, impact = apply_edit_operation(sid, op="exclude_all_pii", params={})
    assert impact["pii_fields_excluded"] >= 1
    email_f = next(f for f in schema.fields if f.field_name == "email")
    assert email_f.include is False

    # 4. Cascade check: removing field with dependent prompts
    # Removing 'timestamp' which is used by 'is_weekend_login'
    schema, impact = apply_edit_operation(
        sid,
        op="remove_field",
        params={"field_name": "timestamp", "cascade": True},
    )
    assert "is_weekend_login" in impact["affected_dependents"]
    ts_f = next(f for f in schema.fields if f.field_name == "timestamp")
    assert ts_f.include is False
    weekend_f = next(f for f in schema.fields if f.field_name == "is_weekend_login")
    assert weekend_f.include is False

    # 5. Undo operation
    undone = undo_operation(sid)
    # Weekend login was restored to included
    weekend_f_after = next(f for f in undone.fields if f.field_name == "is_weekend_login")
    assert weekend_f_after.include is True

    # 6. Redo operation
    redone = redo_operation(sid)
    weekend_f_redone = next(f for f in redone.fields if f.field_name == "is_weekend_login")
    assert weekend_f_redone.include is False

    # 7. Diff against AI proposal
    diff = diff_against_ai_proposal(sid)
    assert len(diff["added_fields"]) >= 1

    # 8. Reset to AI proposal restores clean state
    reset_schema = reset_to_ai_proposal(sid)
    assert not any(f.field_name == "custom_tag" for f in reset_schema.fields)
    assert all(f.include for f in reset_schema.fields)


def test_describe_in_words_derivation(mock_multi_source):
    schema = propose_unified_schema(mock_multi_source)
    sid = schema.id

    proposal = derive_field_from_text(sid, "check if the login occurred on weekend")
    assert proposal["field_name"] == "is_weekend_activity"
    assert "is_weekend" in proposal["expression"]
    assert "timestamp" in proposal["referenced_fields"]
