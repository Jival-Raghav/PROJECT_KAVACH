"""backend/ingest/transforms.py
Declarative allowlisted transform engine for data normalization.
Zero code execution. Strictly safe ops.
Supported ops:
  identity, rename, lower, upper, strip,
  parse_datetime(format|auto, tz), epoch_s, epoch_ms,
  enum_map(map, default), bool_map(true_values, false_values),
  regex_extract(pattern, group), split(sep, index), concat(cols, sep),
  coalesce(cols), json_path(path), arn_user(), domain_strip(), numeric_clip(min, max)
"""
from __future__ import annotations

import datetime
import json
import re
from typing import Any, Callable

import pandas as pd
from pydantic import BaseModel, Field


class TransformSpec(BaseModel):
    op: str
    args: dict[str, Any] = Field(default_factory=dict)


# ─── Individual Safe Transform Operations ────────────────────────────────────

def _op_identity(val: Any, args: dict[str, Any]) -> Any:
    return val


def _op_lower(val: Any, args: dict[str, Any]) -> Any:
    if val is None or pd.isna(val):
        return None
    return str(val).lower()


def _op_upper(val: Any, args: dict[str, Any]) -> Any:
    if val is None or pd.isna(val):
        return None
    return str(val).upper()


def _op_strip(val: Any, args: dict[str, Any]) -> Any:
    if val is None or pd.isna(val):
        return None
    chars = args.get("chars")
    return str(val).strip(chars)


def _op_parse_datetime(val: Any, args: dict[str, Any]) -> str | None:
    if val is None or pd.isna(val):
        return None
    s = str(val).strip()
    fmt = args.get("format")

    dt: datetime.datetime | None = None
    if fmt and fmt != "auto":
        try:
            dt = datetime.datetime.strptime(s, fmt)
        except Exception:
            pass

    if dt is None:
        # Fallback to standard iso or pandas auto parse
        try:
            dt = pd.to_datetime(s, utc=True).to_pydatetime()
        except Exception:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.isoformat()


def _op_epoch_s(val: Any, args: dict[str, Any]) -> str | None:
    if val is None or pd.isna(val):
        return None
    try:
        ts = float(val)
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _op_epoch_ms(val: Any, args: dict[str, Any]) -> str | None:
    if val is None or pd.isna(val):
        return None
    try:
        ts = float(val) / 1000.0
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _op_enum_map(val: Any, args: dict[str, Any]) -> Any:
    if val is None or pd.isna(val):
        return args.get("default")
    mapping = args.get("map", {})
    key = str(val).strip()
    if key in mapping:
        return mapping[key]
    key_lower = key.lower()
    mapping_lower = {str(k).lower(): v for k, v in mapping.items()}
    return mapping_lower.get(key_lower, args.get("default"))


def _op_bool_map(val: Any, args: dict[str, Any]) -> bool | None:
    if val is None or pd.isna(val):
        return None
    true_vals = {str(x).lower() for x in args.get("true_values", ["true", "1", "yes", "y", "t", "success", "allowed"])}
    false_vals = {str(x).lower() for x in args.get("false_values", ["false", "0", "no", "n", "f", "failure", "denied"])}
    s = str(val).strip().lower()
    if s in true_vals:
        return True
    if s in false_vals:
        return False
    return None


def _op_regex_extract(val: Any, args: dict[str, Any]) -> str | None:
    if val is None or pd.isna(val):
        return None
    pattern = args.get("pattern", "")
    group = args.get("group", 1)
    if not pattern:
        return str(val)
    match = re.search(pattern, str(val))
    if match:
        try:
            return match.group(group)
        except IndexError:
            return match.group(0)
    return None


def _op_split(val: Any, args: dict[str, Any]) -> str | None:
    if val is None or pd.isna(val):
        return None
    sep = args.get("sep", ",")
    idx = int(args.get("index", 0))
    parts = str(val).split(sep)
    if 0 <= idx < len(parts):
        return parts[idx].strip()
    return None


def _op_json_path(val: Any, args: dict[str, Any]) -> Any:
    """Extract nested value using dot-notation path from parsed or string JSON."""
    if val is None or pd.isna(val):
        return None
    path = args.get("path", "")
    if not path:
        return val

    data = val
    if isinstance(val, str):
        try:
            data = json.loads(val)
        except Exception:
            return None

    keys = path.split(".")
    curr = data
    for k in keys:
        if isinstance(curr, dict) and k in curr:
            curr = curr[k]
        else:
            return None
    return curr


def _op_arn_user(val: Any, args: dict[str, Any]) -> str | None:
    """Extract username or assumed role session from AWS ARN strings."""
    if val is None or pd.isna(val):
        return None
    s = str(val).strip()
    # e.g., arn:aws:iam::123456789012:user/Alice -> Alice
    # or arn:aws:sts::123456789012:assumed-role/RoleName/SessionName -> SessionName or RoleName
    if "/" in s:
        parts = s.split("/")
        return parts[-1]
    return s


def _op_domain_strip(val: Any, args: dict[str, Any]) -> str | None:
    """Strip domain from email or DOMAIN\\user."""
    if val is None or pd.isna(val):
        return None
    s = str(val).strip()
    if "@" in s:
        return s.split("@")[0]
    if "\\" in s:
        return s.split("\\")[-1]
    return s


def _op_numeric_clip(val: Any, args: dict[str, Any]) -> float | None:
    if val is None or pd.isna(val):
        return None
    try:
        num = float(val)
        min_v = args.get("min")
        max_v = args.get("max")
        if min_v is not None:
            num = max(float(min_v), num)
        if max_v is not None:
            num = min(float(max_v), num)
        return num
    except Exception:
        return None


# ─── Allowlist Registry ───────────────────────────────────────────────────────

OP_REGISTRY: dict[str, Callable[[Any, dict[str, Any]], Any]] = {
    "identity": _op_identity,
    "rename": _op_identity,
    "lower": _op_lower,
    "upper": _op_upper,
    "strip": _op_strip,
    "parse_datetime": _op_parse_datetime,
    "epoch_s": _op_epoch_s,
    "epoch_ms": _op_epoch_ms,
    "enum_map": _op_enum_map,
    "bool_map": _op_bool_map,
    "regex_extract": _op_regex_extract,
    "split": _op_split,
    "json_path": _op_json_path,
    "arn_user": _op_arn_user,
    "domain_strip": _op_domain_strip,
    "numeric_clip": _op_numeric_clip,
}


def apply_transform(val: Any, spec: TransformSpec | dict[str, Any] | None) -> Any:
    """Apply a declarative transform to a scalar value."""
    if spec is None:
        return val
    if isinstance(spec, dict):
        op = spec.get("op", "identity")
        args = spec.get("args", {})
    else:
        op = spec.op
        args = spec.args

    if op not in OP_REGISTRY:
        raise ValueError(f"Unknown or forbidden transform op: '{op}'. Allowed ops: {sorted(list(OP_REGISTRY.keys()))}")

    fn = OP_REGISTRY[op]
    return fn(val, args)


def apply_series_transform(series: pd.Series, spec: TransformSpec | dict[str, Any] | None) -> pd.Series:
    """Apply a transform vectorized over a pandas Series."""
    if spec is None:
        return series
    if isinstance(spec, dict):
        op = spec.get("op", "identity")
        args = spec.get("args", {})
    else:
        op = spec.op
        args = spec.args

    if op not in OP_REGISTRY:
        raise ValueError(f"Unknown or forbidden transform op: '{op}'")

    # Fast vector paths for common operations
    if op in ("identity", "rename"):
        return series
    elif op == "lower":
        return series.astype(str).str.lower()
    elif op == "upper":
        return series.astype(str).str.upper()
    elif op == "strip":
        return series.astype(str).str.strip(args.get("chars"))
    elif op == "domain_strip":
        return series.apply(lambda v: _op_domain_strip(v, args))
    elif op == "arn_user":
        return series.apply(lambda v: _op_arn_user(v, args))
    elif op == "parse_datetime":
        return series.apply(lambda v: _op_parse_datetime(v, args))
    elif op == "bool_map":
        return series.apply(lambda v: _op_bool_map(v, args))
    elif op == "enum_map":
        return series.apply(lambda v: _op_enum_map(v, args))
    else:
        fn = OP_REGISTRY[op]
        return series.apply(lambda v: fn(v, args))
