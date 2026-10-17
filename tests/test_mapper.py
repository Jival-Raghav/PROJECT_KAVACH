"""tests/test_mapper.py
Tests for Schema Autopilot mapping accuracy and persistence of learned corrections
via the mapping_feedback database table.
"""
from __future__ import annotations

import pandas as pd

from core.db import MappingFeedbackRecord, get_session
from ingest.heuristic_mapper import (
    compute_source_fingerprint,
    map_columns_heuristic,
)
from ingest.profiler import profile_dataframe


def test_mapper_learning_from_corrections():
    # Synthetic dataframe with custom unknown column 'custom_actor_id'
    df = pd.DataFrame([
        {"custom_actor_id": "u101", "event_ts": "2026-03-20T10:00:00Z", "action": "LOGIN"},
    ])
    prof = profile_dataframe(df)
    fp = compute_source_fingerprint(list(df.columns))

    # Before correction: custom_actor_id might not be mapped or has default heuristic
    map_columns_heuristic(prof, target_role="events")

    # Simulate human correcting the mapping: custom_actor_id -> user_key
    session = get_session()
    feedback = MappingFeedbackRecord(
        fingerprint=fp,
        source_column="custom_actor_id",
        target_field="user_key",
        role="events",
        transform_op="lower",
    )
    session.add(feedback)
    session.commit()
    session.close()

    # Re-map the same file format: should automatically resolve with confidence 1.0
    cands_after = map_columns_heuristic(prof, target_role="events")
    custom_cand = next((c for c in cands_after if c.source_column == "custom_actor_id"), None)

    assert custom_cand is not None
    assert custom_cand.canonical_field == "user_key"
    assert custom_cand.confidence == 1.0
    assert "Learned from past user correction" in custom_cand.rationale
