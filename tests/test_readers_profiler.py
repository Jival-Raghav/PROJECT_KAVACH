"""tests/test_readers_profiler.py
Tests for multi-format readers (CSV, JSON, JSONL, Parquet, SQL) and statistical/semantic profiler.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ingest.profiler import profile_dataframe
from ingest.readers import flatten_dict, read_file_to_df, read_sql_to_df


def test_flatten_dict_nested():
    nested = {
        "actor": {
            "id": "u123",
            "profile": {
                "email": "alice@acme.corp"
            }
        },
        "action": "login",
        "tags": ["prod", "web"],
    }
    flat = flatten_dict(nested)
    assert flat["actor.id"] == "u123"
    assert flat["actor.profile.email"] == "alice@acme.corp"
    assert flat["action"] == "login"
    assert flat["tags"] == ["prod", "web"]


def test_readers_and_profiler_csv():
    df = read_file_to_df("backend/data/identity_users.csv", row_cap=20)
    assert len(df) == 20
    assert "user_id" in df.columns

    profile = profile_dataframe(df)
    assert profile.row_count == 20
    assert profile.suggested_role == "identities"
    assert profile.role_confidence >= 0.8

    # Check semantic detection
    email_col = next((c for c in profile.columns if c.name == "email"), None)
    assert email_col is not None
    assert email_col.semantic_type == "email"


def test_readers_jsonl_nested():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w+", encoding="utf-8", delete=False) as f:
        f.write('{"timestamp": "2026-03-20T10:00:00Z", "action": "LOGIN", "actor": {"alternateId": "bob@acme.corp"}}\n')
        f.write('{"timestamp": "2026-03-20T11:00:00Z", "action": "LOGOUT", "actor": {"alternateId": "alice@acme.corp"}}\n')
        tmp_name = f.name

    try:
        df = read_file_to_df(tmp_name)
        assert len(df) == 2
        assert "actor.alternateId" in df.columns
        profile = profile_dataframe(df)
        assert profile.suggested_role == "events"
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def test_sql_read_only_enforcement():
    with pytest.raises(ValueError, match="Write operation 'DROP' is not allowed"):
        read_sql_to_df("sqlite:///:memory:", query="DROP TABLE users;")

    with pytest.raises(ValueError, match="Write operation 'INSERT' is not allowed"):
        read_sql_to_df("sqlite:///:memory:", query="INSERT INTO users VALUES (1);")
