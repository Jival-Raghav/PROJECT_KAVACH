"""
tests/test_column_literals.py — Grep test ensuring no raw legacy dataset column names
leak into downstream v2 modules outside backend/ingest/ and legacy_adapter.py.

Per user requirements:
- Flags ONLY the raw header names from the legacy datasets (identity_users.csv / identity_events.csv)
  that are not part of the canonical model specification.
- Canonical field names (e.g. department, job_title, timestamp, action) are permitted anywhere.
- Legacy ingestion/adapter files (under backend/ingest/ or legacy_adapter.py) are permitted to reference raw headers.
"""
import re
from pathlib import Path

# Raw header names unique to the legacy datasets that must never appear in downstream v2 modules
RAW_LEGACY_HEADERS = [
    "systems_access",
    "time_classification",
    "days_inactive",
    "is_active",
    "anomaly_marker",
]

# Active v2 directories refactored to canonical models.
# Phase 0 introduces 'core'. Subsequent phases activate 'resolve' (Ph 2), 'detect' (Ph 3),
# 'llm' (Ph 4), 'graph' (Ph 5), 'remediation' (Ph 5), 'posture' (Ph 6), 'security' (Ph 7), 'api' (Ph 8).
V2_ACTIVE_DIRECTORIES = [
    "core",
    "resolve",
    "detect",
    "llm",
    "graph",
    "remediation",
    "posture",
    "security",
    "api",
]


def test_no_legacy_column_literals_in_v2_core():
    backend_dir = Path(__file__).resolve().parent.parent / "backend"
    violations = []

    for v2_dir_name in V2_ACTIVE_DIRECTORIES:
        target_dir = backend_dir / v2_dir_name
        if not target_dir.exists():
            continue

        for py_file in target_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for header in RAW_LEGACY_HEADERS:
                # Look for string literal references like "systems_access" or 'systems_access'
                pattern = rf"['\"]{header}['\"]"
                matches = list(re.finditer(pattern, content))
                if matches:
                    for m in matches:
                        line_no = content[:m.start()].count("\n") + 1
                        violations.append(
                            f"{py_file.relative_to(backend_dir)}:{line_no} contains raw legacy header '{header}'"
                        )

    assert not violations, (
        "Found raw legacy column header literals in downstream v2 modules:\n"
        + "\n".join(violations)
        + "\nUse canonical model attributes instead."
    )
