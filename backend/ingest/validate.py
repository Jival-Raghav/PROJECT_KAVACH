"""backend/ingest/validate.py
Validation report and Feature-Degradation Matrix evaluator.
Ensures minimum viable inputs are met and computes live detector status.
"""
from __future__ import annotations

from typing import Any
import pandas as pd
from pydantic import BaseModel, Field

from ingest.transforms import apply_series_transform


class DegradationItem(BaseModel):
    feature: str
    status: str  # "active" | "degraded" | "disabled"
    reason: str


class ValidationReport(BaseModel):
    is_valid: bool
    can_run: bool
    total_rows: int
    rows_valid: int
    rows_dropped: int
    field_coverage: dict[str, float] = Field(default_factory=dict)
    parse_failure_rates: dict[str, float] = Field(default_factory=dict)
    timezone_assumptions: list[str] = Field(default_factory=list)
    degradation_matrix: list[DegradationItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def evaluate_degradation_matrix(
    mapped_roles: list[str],
    mapped_canonical_fields: dict[str, list[str]],
) -> list[DegradationItem]:
    """Compute the status of all downstream detectors based on available tables and fields."""
    items: list[DegradationItem] = []

    # 1. Identity Resolution
    if "identities" in mapped_roles:
        items.append(DegradationItem(
            feature="Identity Resolution",
            status="active",
            reason="HR/Identity records provided. Multi-source linking enabled.",
        ))
    else:
        items.append(DegradationItem(
            feature="Identity Resolution",
            status="disabled",
            reason="Identities table missing. Users derived from accounts/events; peer groups use behavior clustering.",
        ))

    # 2. Entitlement Analytics & SoD
    if "entitlements" in mapped_roles:
        items.append(DegradationItem(
            feature="Privilege Creep & SoD Matrix",
            status="active",
            reason="Entitlement mapping active.",
        ))
    else:
        items.append(DegradationItem(
            feature="Privilege Creep & SoD Matrix",
            status="disabled",
            reason="Entitlements missing. SoD violations, unused entitlements, and attack path calculations disabled.",
        ))

    # 3. Sensitivity / Crown Jewels
    event_fields = mapped_canonical_fields.get("events", [])
    if "resource_sensitivity" in event_fields or "systems" in mapped_roles:
        items.append(DegradationItem(
            feature="Crown Jewel Sensitivity Scoring",
            status="active",
            reason="Sensitivity classifications mapped.",
        ))
    else:
        items.append(DegradationItem(
            feature="Crown Jewel Sensitivity Scoring",
            status="degraded",
            reason="Sensitivity column unmapped. Falling back to default medium-tier weights until user tags systems.",
        ))

    # 4. MFA Posture Subscore
    acct_fields = mapped_canonical_fields.get("accounts", [])
    if "mfa_enabled" in acct_fields:
        items.append(DegradationItem(
            feature="MFA Coverage Subscore",
            status="active",
            reason="MFA authentication status mapped.",
        ))
    else:
        items.append(DegradationItem(
            feature="MFA Coverage Subscore",
            status="degraded",
            reason="MFA unmapped. Posture score will reweight other identity hygiene dimensions.",
        ))

    # 5. Org Context (Devil's Advocate)
    org_roles = {"org_oncall", "org_leave", "org_tickets", "org_projects", "org_hr"}
    present_org = org_roles.intersection(set(mapped_roles))
    if present_org:
        items.append(DegradationItem(
            feature="Devil's Advocate (Org Context)",
            status="active",
            reason=f"Correlating with organizational context: {', '.join(present_org)}.",
        ))
    else:
        items.append(DegradationItem(
            feature="Devil's Advocate (Org Context)",
            status="degraded",
            reason="No ticketing/leave/on-call data found. Rebuttals will rely strictly on peer & behavioral baselines.",
        ))

    # 6. Evaluation / Label Ground Truth
    if "label" in event_fields:
        items.append(DegradationItem(
            feature="Ground Truth Metrics (F1 / PR-AUC)",
            status="active",
            reason="Event ground-truth labels provided.",
        ))
    else:
        items.append(DegradationItem(
            feature="Ground Truth Metrics (F1 / PR-AUC)",
            status="degraded",
            reason="Labels missing. Metrics reported as 'unlabelled - precision unknown'.",
        ))

    return items


def validate_source_mapping(
    df: pd.DataFrame,
    role: str,
    mappings: list[dict[str, Any]],  # canonical_field, source_column, transform
) -> ValidationReport:
    """Validate mapped DataFrame and check minimum viable inputs."""
    total_rows = len(df)
    warnings: list[str] = []
    errors: list[str] = []
    field_coverage: dict[str, float] = {}
    parse_failures: dict[str, float] = {}
    tz_assumptions: list[str] = []

    mapped_canonicals = {m["canonical_field"] for m in mappings}

    # Minimum Viable Input check for events
    if role == "events":
        has_ts = "timestamp" in mapped_canonicals
        has_user = "user_key" in mapped_canonicals
        has_act_or_res = ("action" in mapped_canonicals) or ("resource" in mapped_canonicals)

        if not has_ts:
            errors.append("Minimum viable input violated: Missing 'timestamp' field.")
        if not has_user:
            errors.append("Minimum viable input violated: Missing 'user_key' (actor/username) field.")
        if not has_act_or_res:
            errors.append("Minimum viable input violated: Need at least 'action' OR 'resource' field.")

    # Test transforms on a sample (up to 200 rows)
    sample_df = df.head(200)

    for m in mappings:
        c_field = m["canonical_field"]
        s_col = m["source_column"]
        transform_spec = m.get("transform", {"op": "identity"})

        if s_col not in sample_df.columns:
            errors.append(f"Mapped source column '{s_col}' not found in dataset.")
            continue

        raw_series = sample_df[s_col]
        non_null_raw = raw_series.dropna()
        field_coverage[c_field] = round(float(len(non_null_raw) / len(sample_df)), 4) if len(sample_df) > 0 else 0.0

        try:
            transformed = apply_series_transform(raw_series, transform_spec)
            # Check parse failures (where raw was non-null but transform returned None)
            failures = sum(1 for r, t in zip(raw_series, transformed) if pd.notna(r) and pd.isna(t))
            fail_rate = float(failures / len(non_null_raw)) if len(non_null_raw) > 0 else 0.0
            parse_failures[c_field] = round(fail_rate, 4)

            if fail_rate > 0.05:
                warnings.append(f"High parse failure rate ({int(fail_rate*100)}%) on field '{c_field}' using transform '{transform_spec.get('op')}'.")

            if c_field == "timestamp" and transform_spec.get("op") == "parse_datetime":
                tz = transform_spec.get("args", {}).get("tz", "UTC")
                tz_assumptions.append(f"Assuming timezone '{tz}' for parsed timestamps without offset.")

        except Exception as e:
            errors.append(f"Transform failure on '{c_field}': {e}")
            parse_failures[c_field] = 1.0

    can_run = len(errors) == 0
    degradation = evaluate_degradation_matrix([role], {role: list(mapped_canonicals)})

    return ValidationReport(
        is_valid=len(errors) == 0,
        can_run=can_run,
        total_rows=total_rows,
        rows_valid=total_rows,
        rows_dropped=0,
        field_coverage=field_coverage,
        parse_failure_rates=parse_failures,
        timezone_assumptions=tz_assumptions,
        degradation_matrix=degradation,
        warnings=warnings,
        errors=errors,
    )
