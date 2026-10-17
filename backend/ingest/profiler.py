"""backend/ingest/profiler.py
Statistical and semantic profiler for tabular data columns and table-role classifier.
Detects semantic data types (email, uuid, ip, timestamp, etc.) and classifies table roles.
"""
from __future__ import annotations

import re
from typing import Any

import pandas as pd
from pydantic import BaseModel, Field


# ─── Semantic Regex Patterns ──────────────────────────────────────────────────
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6_REGEX = re.compile(r"^[0-9a-fA-F:]+$")
ISO_DATETIME_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$")
DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
EMPLOYEE_ID_REGEX = re.compile(r"^(?:EMP|ID|E|U)?[0-9]{3,8}$", re.IGNORECASE)
BOOL_VALUES = {"true", "false", "1", "0", "yes", "no", "y", "n", "t", "f"}


class ColumnProfile(BaseModel):
    name: str
    dtype: str
    null_rate: float
    cardinality: int
    top_values: list[Any] = Field(default_factory=list)
    min_val: Any = None
    max_val: Any = None
    length_min: int = 0
    length_max: int = 0
    length_mean: float = 0.0
    semantic_type: str = "unknown"


class TableProfile(BaseModel):
    row_count: int
    column_count: int
    columns: list[ColumnProfile]
    suggested_role: str = "unknown"
    role_confidence: float = 0.0


def _detect_semantic_type(series: pd.Series, col_name: str) -> str:
    """Infer semantic type from non-null string samples and column name."""
    clean_series = series.dropna().astype(str).str.strip()
    if clean_series.empty:
        return "unknown"

    sample = clean_series.head(100)
    total = len(sample)
    if total == 0:
        return "unknown"

    # Boolean-like
    bool_matches = sum(1 for v in sample if v.lower() in BOOL_VALUES)
    if bool_matches / total >= 0.90:
        return "boolean-like"

    # Epoch timestamps (numeric string or int/float)
    if pd.api.types.is_numeric_dtype(series):
        non_null_num = series.dropna()
        if not non_null_num.empty:
            sample_val = float(non_null_num.iloc[0])
            # epoch_s typically between 1_000_000_000 and 2_500_000_000 (2001 - 2049)
            if 1_000_000_000 <= sample_val <= 2_500_000_000:
                return "epoch_s"
            # epoch_ms typically between 1_000_000_000_000 and 2_500_000_000_000
            elif 1_000_000_000_000 <= sample_val <= 2_500_000_000_000:
                return "epoch_ms"

    # Email
    email_matches = sum(1 for v in sample if EMAIL_REGEX.match(v))
    if email_matches / total >= 0.70:
        return "email"

    # UUID
    uuid_matches = sum(1 for v in sample if UUID_REGEX.match(v))
    if uuid_matches / total >= 0.70:
        return "uuid"

    # IPv4 / IPv6
    ip_matches = sum(1 for v in sample if IPV4_REGEX.match(v) or (":" in v and IPV6_REGEX.match(v)))
    if ip_matches / total >= 0.70:
        return "ipv4/6"

    # ISO Datetime
    iso_matches = sum(1 for v in sample if ISO_DATETIME_REGEX.match(v))
    if iso_matches / total >= 0.70:
        return "iso_datetime"

    # Date
    date_matches = sum(1 for v in sample if DATE_REGEX.match(v))
    if date_matches / total >= 0.70:
        return "date"

    # Employee ID-like
    emp_matches = sum(1 for v in sample if EMPLOYEE_ID_REGEX.match(v))
    name_hints = any(k in col_name.lower() for k in ("emp", "employee", "badge", "staff_id"))
    if (emp_matches / total >= 0.70) or (name_hints and emp_matches / total >= 0.30):
        return "employee_id-like"

    # URL / Hostname
    url_matches = sum(1 for v in sample if v.startswith("http://") or v.startswith("https://"))
    if url_matches / total >= 0.50:
        return "url"

    # Free text
    avg_len = clean_series.str.len().mean()
    if avg_len > 60:
        return "free_text"

    return "unknown"


def mask_sample_value(val: Any, semantic_type: str) -> Any:
    """Mask PII in sample values for safe profiling displays."""
    if val is None or pd.isna(val):
        return None
    s = str(val)
    if semantic_type == "email":
        parts = s.split("@")
        if len(parts) == 2:
            user, domain = parts
            masked_user = (user[:2] + "***") if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
    elif semantic_type == "ipv4/6":
        parts = s.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
    return s[:100]  # truncate overly long strings


def profile_column(series: pd.Series, name: str) -> ColumnProfile:
    """Generate comprehensive statistical and semantic profile for a single column."""
    total_len = len(series)
    null_count = series.isna().sum()
    null_rate = float(null_count / total_len) if total_len > 0 else 0.0

    valid_series = series.dropna()
    cardinality = int(valid_series.nunique())

    sem_type = _detect_semantic_type(series, name)

    # Top sample values (up to 10 most frequent)
    top_vals_raw = valid_series.value_counts().head(10).index.tolist()
    top_values = [mask_sample_value(v, sem_type) for v in top_vals_raw]

    # Min / Max
    min_val, max_val = None, None
    if not valid_series.empty:
        try:
            if pd.api.types.is_numeric_dtype(series):
                min_val = float(valid_series.min())
                max_val = float(valid_series.max())
            else:
                min_val = str(valid_series.min())[:50]
                max_val = str(valid_series.max())[:50]
        except Exception:
            pass

    # String length statistics
    str_lens = valid_series.astype(str).str.len()
    l_min = int(str_lens.min()) if not str_lens.empty else 0
    l_max = int(str_lens.max()) if not str_lens.empty else 0
    l_mean = float(str_lens.mean()) if not str_lens.empty else 0.0

    return ColumnProfile(
        name=str(name),
        dtype=str(series.dtype),
        null_rate=round(null_rate, 4),
        cardinality=cardinality,
        top_values=top_values,
        min_val=min_val,
        max_val=max_val,
        length_min=l_min,
        length_max=l_max,
        length_mean=round(l_mean, 2),
        semantic_type=sem_type,
    )


def classify_table_role(col_names: list[str], col_profiles: list[ColumnProfile]) -> tuple[str, float]:
    """Heuristic table-role classifier.
    Returns (role, confidence).
    Roles: identities, accounts, entitlements, events, systems, org_oncall,
           org_leave, org_tickets, org_projects, org_hr, unknown.
    """
    names_lower = [c.lower() for c in col_names]
    sem_types = {p.name.lower(): p.semantic_type for p in col_profiles}

    score_map: dict[str, float] = {
        "identities": 0.0,
        "accounts": 0.0,
        "entitlements": 0.0,
        "events": 0.0,
        "systems": 0.0,
        "org_oncall": 0.0,
        "org_leave": 0.0,
        "org_tickets": 0.0,
        "org_projects": 0.0,
        "org_hr": 0.0,
    }

    # Events indicators
    has_timestamp = any(
        any(t in n for t in ("time", "ts", "date", "created")) or sem_types.get(n) in ("iso_datetime", "epoch_s", "epoch_ms")
        for n in names_lower
    )
    has_action = any(any(a in n for a in ("action", "event_name", "eventname", "operation", "verb", "activity")) for n in names_lower)
    has_resource = any(any(r in n for r in ("resource", "object", "target", "path", "uri", "asset")) for n in names_lower)
    has_ip = any(sem_types.get(n) == "ipv4/6" or "ip" in n for n in names_lower)

    if has_timestamp and (has_action or has_resource):
        score_map["events"] += 3.5
    if has_ip:
        score_map["events"] += 1.5

    # Identities indicators
    has_full_name = any(any(k in n for k in ("name", "full_name", "displayname", "first_name")) for n in names_lower)
    has_dept = any(any(k in n for k in ("dept", "department", "division", "team", "organization")) for n in names_lower)
    has_job = any(any(k in n for k in ("title", "job_title", "role", "position")) for n in names_lower)
    has_status = any(any(k in n for k in ("status", "employment_status", "hire_date", "termination_date")) for n in names_lower)
    has_email = any(sem_types.get(n) == "email" or "email" in n for n in names_lower)

    if has_dept and (has_full_name or has_job):
        score_map["identities"] += 3.0
    if has_status:
        score_map["identities"] += 1.5
    if has_email:
        score_map["identities"] += 1.0

    # Accounts indicators
    has_username = any(any(k in n for k in ("username", "login", "user_key", "principal", "account_name")) for n in names_lower)
    has_system = any(any(k in n for k in ("system", "application", "app", "target_system")) for n in names_lower)
    has_mfa = any(any(k in n for k in ("mfa", "mfa_enabled", "2fa")) for n in names_lower)
    has_acct_type = any(any(k in n for k in ("account_type", "type", "privileged", "admin")) for n in names_lower)

    if has_username and has_system and not has_action:
        score_map["accounts"] += 3.0
    if has_mfa:
        score_map["accounts"] += 1.5
    if has_acct_type and not has_action:
        score_map["accounts"] += 1.0

    # Entitlements indicators
    has_entitlement = any(any(k in n for k in ("entitlement", "privilege", "permission", "group", "role_name", "policy")) for n in names_lower)
    if has_entitlement and (has_system or has_username or "weight" in "".join(names_lower)):
        score_map["entitlements"] += 4.0

    # Systems indicators
    if has_system and any(any(k in n for k in ("sensitivity", "tier", "owner", "criticality")) for n in names_lower):
        score_map["systems"] += 4.0

    # Org context indicators
    if any("oncall" in n or "on_call" in n or "shift" in n for n in names_lower):
        score_map["org_oncall"] += 4.5
    if any("leave" in n or "pto" in n or "vacation" in n or "absence" in n for n in names_lower):
        score_map["org_leave"] += 4.5
    if any("ticket" in n or "jira" in n or "change_req" in n for n in names_lower):
        score_map["org_tickets"] += 4.5
    if any("project" in n for n in names_lower) and not has_action:
        score_map["org_projects"] += 4.0
    if any("transfer" in n or "promotion" in n or "hr_event" in n for n in names_lower):
        score_map["org_hr"] += 4.5

    best_role = max(score_map, key=score_map.get)
    best_score = score_map[best_role]

    if best_score < 2.0:
        return "unknown", 0.30

    confidence = min(0.95, round(best_score / 5.0, 2))
    return best_role, confidence


def profile_dataframe(df: pd.DataFrame) -> TableProfile:
    """Compute full profile for a pandas DataFrame."""
    col_profiles: list[ColumnProfile] = []
    for col in df.columns:
        col_profiles.append(profile_column(df[col], str(col)))

    role, confidence = classify_table_role(list(df.columns), col_profiles)

    return TableProfile(
        row_count=len(df),
        column_count=len(df.columns),
        columns=col_profiles,
        suggested_role=role,
        role_confidence=confidence,
    )
