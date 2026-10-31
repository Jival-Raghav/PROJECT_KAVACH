"""backend/ingest/dsl.py
Restricted Expression Language for Unified Schema Editor derived fields.
Enforces zero code execution via AST-sandboxed allowlisting.
Rejects hostile expressions: __import__, attribute traversal, arbitrary globals,
large exponents, infinite loops, and excessive AST depth.
"""
from __future__ import annotations

import ast
import datetime
import math
import re
from typing import Any, Callable

import pandas as pd


MAX_EXPR_LENGTH = 500
MAX_AST_DEPTH = 15

# ─── Allowed AST Node Types ───────────────────────────────────────────────────
ALLOWED_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.Call,
    ast.Name,
    ast.Constant,
    ast.List,
    ast.Tuple,
    ast.IfExp,
    # Operators
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.FloorDiv,
    ast.Not,
    ast.UAdd,
    ast.USub,
    ast.And,
    ast.Or,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Load,
)


# ─── Allowed Builtin DSL Functions ────────────────────────────────────────────

def dsl_coalesce(*args: Any) -> Any:
    for a in args:
        if a is not None and not (isinstance(a, float) and math.isnan(a)) and a != "":
            return a
    return None


def dsl_lower(val: Any) -> str | None:
    return str(val).lower() if val is not None else None


def dsl_upper(val: Any) -> str | None:
    return str(val).upper() if val is not None else None


def dsl_concat(*args: Any) -> str:
    return "".join(str(a) for a in args if a is not None)


def dsl_len(val: Any) -> int:
    return len(str(val)) if val is not None else 0


def dsl_contains(s: Any, sub: Any) -> bool:
    if s is None or sub is None:
        return False
    return str(sub) in str(s)


def dsl_startswith(s: Any, prefix: Any) -> bool:
    if s is None or prefix is None:
        return False
    return str(s).startswith(str(prefix))


def dsl_endswith(s: Any, suffix: Any) -> bool:
    if s is None or suffix is None:
        return False
    return str(s).endswith(str(suffix))


def dsl_regex_extract(s: Any, pattern: str, group: int = 1) -> str | None:
    if s is None or not pattern:
        return None
    match = re.search(str(pattern), str(s))
    if match:
        try:
            return match.group(int(group))
        except IndexError:
            return match.group(0)
    return None


def _parse_ts(val: Any) -> datetime.datetime | None:
    if val is None or pd.isna(val):
        return None
    try:
        dt = pd.to_datetime(str(val), utc=True).to_pydatetime()
        return dt
    except Exception:
        return None


def dsl_date_diff_days(d1: Any, d2: Any) -> float | None:
    dt1 = _parse_ts(d1)
    dt2 = _parse_ts(d2)
    if dt1 and dt2:
        return abs((dt1 - dt2).total_seconds()) / 86400.0
    return None


def dsl_hour(ts: Any) -> int | None:
    dt = _parse_ts(ts)
    return dt.hour if dt else None


def dsl_weekday(ts: Any) -> int | None:
    dt = _parse_ts(ts)
    return dt.weekday() if dt else None


def dsl_is_weekend(ts: Any) -> bool | None:
    dt = _parse_ts(ts)
    return (dt.weekday() in (5, 6)) if dt else None


def dsl_bucket(x: Any, edges: list[float]) -> str | None:
    if x is None or pd.isna(x):
        return None
    try:
        val = float(x)
        sorted_edges = sorted(edges)
        for i, edge in enumerate(sorted_edges):
            if val < edge:
                return f"<{edge}"
        return f">={sorted_edges[-1]}"
    except Exception:
        return None


def dsl_ratio(a: Any, b: Any) -> float:
    try:
        denom = float(b)
        if denom == 0.0 or math.isnan(denom):
            return 0.0
        num = float(a)
        return num / denom
    except Exception:
        return 0.0


def dsl_if(cond: Any, a: Any, b: Any) -> Any:
    return a if cond else b


def dsl_in(x: Any, lst: list[Any]) -> bool:
    try:
        return x in lst
    except Exception:
        return False


def dsl_round(x: Any, n: int = 0) -> float | None:
    try:
        return round(float(x), int(n))
    except Exception:
        return None


def dsl_min(*args: Any) -> float | None:
    try:
        vals = [float(a) for a in args if a is not None and not pd.isna(a)]
        return min(vals) if vals else None
    except Exception:
        return None


def dsl_max(*args: Any) -> float | None:
    try:
        vals = [float(a) for a in args if a is not None and not pd.isna(a)]
        return max(vals) if vals else None
    except Exception:
        return None


def dsl_abs(x: Any) -> float | None:
    try:
        return abs(float(x))
    except Exception:
        return None


def dsl_is_null(x: Any) -> bool:
    return x is None or pd.isna(x) or str(x).strip() == ""


DSL_FUNCTIONS: dict[str, Callable] = {
    "coalesce": dsl_coalesce,
    "lower": dsl_lower,
    "upper": dsl_upper,
    "concat": dsl_concat,
    "len": dsl_len,
    "contains": dsl_contains,
    "startswith": dsl_startswith,
    "endswith": dsl_endswith,
    "regex_extract": dsl_regex_extract,
    "date_diff_days": dsl_date_diff_days,
    "hour": dsl_hour,
    "weekday": dsl_weekday,
    "is_weekend": dsl_is_weekend,
    "bucket": dsl_bucket,
    "ratio": dsl_ratio,
    "if": dsl_if,
    "dsl_if": dsl_if,
    "in": dsl_in,
    "round": dsl_round,
    "min": dsl_min,
    "max": dsl_max,
    "abs": dsl_abs,
    "is_null": dsl_is_null,
}


class DSLExpression:
    def __init__(self, raw_expr: str):
        self.raw_expr = raw_expr
        self.field_map: dict[str, str] = {}  # token -> original field name
        self.rev_field_map: dict[str, str] = {}  # original field name -> token
        self.sanitized_expr = self._preprocess(raw_expr)
        self.ast_tree = self._validate_and_compile(self.sanitized_expr)

    def _preprocess(self, expr: str) -> str:
        if len(expr) > MAX_EXPR_LENGTH:
            raise ValueError(f"Expression exceeds maximum length of {MAX_EXPR_LENGTH} characters.")

        # Replace ${field_name} with safe identifiers _fld_0, _fld_1, ...
        pattern = re.compile(r"\$\{([^}]+)\}")
        token_counter = 0

        def replace_field(match: re.Match) -> str:
            nonlocal token_counter
            field_name = match.group(1).strip()
            if field_name not in self.rev_field_map:
                token = f"_fld_{token_counter}"
                token_counter += 1
                self.field_map[token] = field_name
                self.rev_field_map[field_name] = token
            return self.rev_field_map[field_name]

        sanitized = pattern.sub(replace_field, expr)
        # Convert function-call-style if(...) to dsl_if(...)
        sanitized = re.sub(r"\bif\s*\(", "dsl_if(", sanitized)
        return sanitized

    def _validate_and_compile(self, expr: str) -> ast.Expression:
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError as e:
            raise ValueError(f"Syntax error in expression: {e}") from e

        # Validate AST depth and node allowlist
        def check_node(node: ast.AST, depth: int) -> None:
            if depth > MAX_AST_DEPTH:
                raise ValueError(f"Expression exceeds maximum AST depth of {MAX_AST_DEPTH}.")

            if not isinstance(node, ALLOWED_NODES):
                raise ValueError(f"Disallowed expression element: {type(node).__name__}")

            # Disallow exponentiation (Pow) to prevent huge resource consumption
            if isinstance(node, ast.Pow):
                raise ValueError("Exponentiation operator '**' is forbidden in DSL expressions.")

            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name):
                    raise ValueError("Only direct function calls to allowlisted DSL functions are permitted.")
                func_name = node.func.id
                if func_name not in DSL_FUNCTIONS:
                    raise ValueError(f"Forbidden function call: '{func_name}'. Allowed: {sorted(list(DSL_FUNCTIONS.keys()))}")

            if isinstance(node, ast.Name):
                name = node.id
                if name not in self.field_map and name not in DSL_FUNCTIONS and name not in ("True", "False", "None"):
                    raise ValueError(f"Unknown or unauthorized identifier: '{name}'. Did you mean ${{field}}?")

            for child in ast.iter_child_nodes(node):
                check_node(child, depth + 1)

        check_node(tree, 1)
        return tree

    @property
    def referenced_fields(self) -> list[str]:
        """List of original canonical/source field names referenced by this expression."""
        return list(self.field_map.values())

    def evaluate_row(self, row: dict[str, Any]) -> Any:
        """Safely evaluate expression against a single record."""
        # Create execution environment containing only field tokens and allowlisted functions
        eval_env: dict[str, Any] = dict(DSL_FUNCTIONS)
        for token, original_field in self.field_map.items():
            eval_env[token] = row.get(original_field)

        # Builtins are completely cleared to prevent access to __import__, open, eval, etc.
        eval_env["__builtins__"] = {}

        compiled = compile(self.ast_tree, filename="<dsl>", mode="eval")
        return eval(compiled, eval_env)

    def evaluate_df(self, df: pd.DataFrame) -> pd.Series:
        """Evaluate expression across a DataFrame with clean null and type handling."""
        records = df.to_dict(orient="records")
        results = [self.evaluate_row(r) for r in records]
        return pd.Series(results, index=df.index)
