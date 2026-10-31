"""tests/test_transforms_dsl.py
Comprehensive test suite for declarative safe transforms and AST-sandboxed DSL.
Includes >=20 hostile expressions (arbitrary execution, imports, traversal, memory bombs)
verifying zero execution and safe rejection.
"""
from __future__ import annotations

import pandas as pd
import pytest

from ingest.dsl import DSLExpression, MAX_AST_DEPTH, MAX_EXPR_LENGTH
from ingest.transforms import apply_transform


# ─── 1. Declarative Safe Transforms Tests ─────────────────────────────────────

def test_safe_transforms_basic():
    # Lower, Upper, Strip
    assert apply_transform("  ALICE  ", {"op": "lower"}) == "  alice  "
    assert apply_transform("  ALICE  ", {"op": "strip"}) == "ALICE"
    assert apply_transform("bob", {"op": "upper"}) == "BOB"

    # Domain strip
    assert apply_transform("alice@company.com", {"op": "domain_strip"}) == "alice"
    assert apply_transform("CORP\\alice", {"op": "domain_strip"}) == "alice"

    # ARN user extraction
    assert apply_transform("arn:aws:iam::123456789012:user/rohan.verma", {"op": "arn_user"}) == "rohan.verma"
    assert apply_transform("arn:aws:sts::123456789012:assumed-role/SecOps/session1", {"op": "arn_user"}) == "session1"

    # Bool map
    assert apply_transform("YES", {"op": "bool_map"}) is True
    assert apply_transform("0", {"op": "bool_map"}) is False
    assert apply_transform("SUCCESS", {"op": "bool_map"}) is True

    # Numeric clip
    assert apply_transform(150, {"op": "numeric_clip", "args": {"min": 0, "max": 100}}) == 100.0
    assert apply_transform(-10, {"op": "numeric_clip", "args": {"min": 0, "max": 100}}) == 0.0

    # Date parsing
    parsed_iso = apply_transform("2026-03-20T10:15:30Z", {"op": "parse_datetime"})
    assert "2026-03-20T10:15:30" in str(parsed_iso)

    # Epoch ms
    epoch_iso = apply_transform(1700000000000, {"op": "epoch_ms"})
    assert epoch_iso is not None


def test_reject_forbidden_transform():
    with pytest.raises(ValueError, match="Unknown or forbidden"):
        apply_transform("data", {"op": "system_exec", "args": {"cmd": "whoami"}})


# ─── 2. Sandboxed DSL Valid Expressions ───────────────────────────────────────

def test_dsl_valid_evaluation():
    row = {
        "timestamp": "2026-03-21T14:30:00Z",  # Saturday
        "login_count": 5,
        "failed_count": 2,
        "status": "SUCCESS",
    }

    # Arithmetic & Functions
    expr1 = DSLExpression("ratio(${failed_count}, ${login_count})")
    assert expr1.evaluate_row(row) == 0.4

    # Date & Weekend detection
    expr2 = DSLExpression("is_weekend(${timestamp})")
    assert expr2.evaluate_row(row) is True

    # Hour function
    expr3 = DSLExpression("hour(${timestamp})")
    assert expr3.evaluate_row(row) == 14

    # Conditional logic
    expr4 = DSLExpression("if(${login_count} > 3, 'high', 'normal')")
    assert expr4.evaluate_row(row) == "high"

    # Coalesce & String ops
    expr5 = DSLExpression("upper(coalesce(${status}, 'unknown'))")
    assert expr5.evaluate_row(row) == "SUCCESS"


def test_dsl_df_evaluation():
    df = pd.DataFrame([
        {"user": "alice", "score": 10},
        {"user": "bob", "score": 25},
    ])
    expr = DSLExpression("${score} * 2")
    res = expr.evaluate_df(df)
    assert list(res) == [20, 50]


# ─── 3. Rejection of >= 20 Hostile Expressions ────────────────────────────────

HOSTILE_EXPRESSIONS = [
    # 1. Direct __import__
    "__import__('os').system('ls')",
    # 2. Builtins traversal
    "__builtins__['eval']('1+1')",
    # 3. Class hierarchy traversal
    "().__class__.__bases__[0].__subclasses__()",
    # 4. Standard eval
    "eval('2 + 2')",
    # 5. Standard exec
    "exec('import sys')",
    # 6. File reading via open
    "open('/etc/passwd').read()",
    # 7. Lambda expressions
    "(lambda x: x + 1)(5)",
    # 8. List comprehensions
    "[x for x in range(10)]",
    # 9. Dict comprehensions
    "{x: x for x in range(5)}",
    # 10. Direct globals access
    "globals()",
    # 11. Direct locals access
    "locals()",
    # 12. getattr invocation
    "getattr(object, '__class__')",
    # 13. hasattr invocation
    "hasattr(object, '__dict__')",
    # 14. compile invocation
    "compile('1+1', '', 'eval')",
    # 15. Huge exponentiation / memory bomb
    "9 ** 9 ** 9",
    # 16. Subscript access on variables
    "${user}[0]",
    # 17. Attribute access on fields
    "${user}.strip",
    # 18. sys module call
    "sys.exit(0)",
    # 19. importlib dynamic import
    "importlib.import_module('os')",
    # 20. breakpoint invocation
    "breakpoint()",
    # 21. quit / exit call
    "quit()",
    # 22. Deeply nested AST
    "1 + (" * (MAX_AST_DEPTH + 2) + "1" + ")" * (MAX_AST_DEPTH + 2),
    # 23. Overly long string
    "1 + " + ("1 + " * (MAX_EXPR_LENGTH // 4)),
]


@pytest.mark.parametrize("hostile_expr", HOSTILE_EXPRESSIONS)
def test_hostile_expression_rejected(hostile_expr: str):
    with pytest.raises(ValueError):
        DSLExpression(hostile_expr)
