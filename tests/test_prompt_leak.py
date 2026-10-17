"""tests/test_prompt_leak.py
Security test asserting that excluded and PII-flagged fields are NEVER leaked
in raw form into any LLM prompt payload.
"""
from __future__ import annotations

import pandas as pd

from ingest.profiler import mask_sample_value, profile_dataframe
from ingest.schema_editor import apply_edit_operation, propose_unified_schema


def test_pii_profiler_masking():
    raw_email = "super_confidential_ceo@enterprise.com"
    masked = mask_sample_value(raw_email, "email")
    assert raw_email not in str(masked)
    assert "***@enterprise.com" in str(masked)

    raw_ip = "192.168.1.100"
    masked_ip = mask_sample_value(raw_ip, "ipv4/6")
    assert raw_ip not in str(masked_ip)
    assert "192.168.*.*" in str(masked_ip)


def test_excluded_and_pii_fields_never_reach_llm_prompts():
    """Verify that when a field is marked include=False or pii=True,
    raw values are strictly absent from formatted prompt text.
    """
    secret_value = "TOP_SECRET_PASSTHROUGH_TOKEN_XYZ987"
    raw_user_email = "victim.whistleblower@enterprise.com"

    df = pd.DataFrame([
        {
            "timestamp": "2026-03-20T10:00:00Z",
            "user_key": "u101",
            "action": "QUERY",
            "email": raw_user_email,
            "secret_token": secret_value,
        }
    ])

    prof = profile_dataframe(df)
    sources = [{"source_id": "src_1", "role": "events", "profile": prof, "df": df}]

    unified = propose_unified_schema(sources)
    sid = unified.id

    # 1. Exclude secret_token
    unified, _ = apply_edit_operation(
        sid,
        op="remove_field",
        params={"field_name": "secret_token"},
    )

    # 2. Exclude all PII
    unified, _ = apply_edit_operation(sid, op="exclude_all_pii", params={})

    # Build simulated LLM prompt payload from active included fields only
    active_fields = [f for f in unified.fields if f.include]
    active_field_names = {f.field_name for f in active_fields}

    # Verify secret_token is not in active fields
    assert "secret_token" not in active_field_names
    assert "email" not in active_field_names

    # Build prompt representation
    prompt_lines = []
    for f in active_fields:
        val = df.iloc[0].get(f.field_name, "")
        prompt_lines.append(f"{f.field_name}: {val}")
    prompt_payload = "\n".join(prompt_lines)

    # STRICT ASSERTIONS: Raw secrets and excluded PII MUST NOT exist anywhere in prompt payload
    assert secret_value not in prompt_payload
    assert raw_user_email not in prompt_payload
    assert "secret_token" not in prompt_payload
    assert "email" not in prompt_payload
