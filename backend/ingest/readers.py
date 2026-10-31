"""backend/ingest/readers.py
Multi-format tabular readers: CSV, TSV, JSON, JSONL, Parquet, and Read-Only SQL.
Flattens nested JSON hierarchies using dot-paths (e.g. actor.alternateId).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import create_engine, text


def flatten_dict(d: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Recursively flatten nested dictionary using dot notation."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # If list contains dicts or scalars, serialize cleanly or keep scalars
            if v and all(isinstance(x, (str, int, float, bool)) for x in v):
                items.append((new_key, v))
            elif v and all(isinstance(x, dict) for x in v):
                # Flatten first element keys for dot-path access (e.g. target.alternateId)
                if len(v) > 0 and isinstance(v[0], dict):
                    for sub_k, sub_v in v[0].items():
                        items.append((f"{new_key}{sep}{sub_k}", sub_v))
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))
        else:
            items.append((new_key, v))
    return dict(items)


def read_file_to_df(
    file_path: str | Path,
    row_cap: int | None = None,
) -> pd.DataFrame:
    """Read a local file (CSV, TSV, JSON, JSONL, Parquet) into a DataFrame.
    Gracefully handles empty files, non-tabular formats, and nested structures.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if path.stat().st_size == 0:
        return pd.DataFrame()

    ext = path.suffix.lower()

    try:
        if ext in (".csv", ".tsv", ".txt"):
            sep = "\t" if ext == ".tsv" else None
            # auto-detect separator if csv
            try:
                df = pd.read_csv(path, sep=sep, engine="python", nrows=row_cap)
            except Exception:
                df = pd.read_csv(path, nrows=row_cap)
            return df

        elif ext == ".parquet":
            df = pd.read_parquet(path)
            if row_cap and len(df) > row_cap:
                df = df.iloc[:row_cap]
            return df

        elif ext in (".json", ".jsonl"):
            # Check if JSONL or standard JSON
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(50000).strip()

            # If multiple lines each starting with '{' or '[', attempt jsonl
            is_jsonl = False
            first_line = content.split("\n")[0].strip() if "\n" in content else content
            if "\n" in content and (first_line.startswith("{") and not content.startswith("[")):
                is_jsonl = True

            records: list[dict[str, Any]] = []
            if is_jsonl:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if row_cap and i >= row_cap:
                            break
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            item = json.loads(line_str)
                            if isinstance(item, dict):
                                records.append(flatten_dict(item))
                        except Exception:
                            continue
            else:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    raw = json.load(f)
                if isinstance(raw, list):
                    for i, item in enumerate(raw):
                        if row_cap and i >= row_cap:
                            break
                        if isinstance(item, dict):
                            records.append(flatten_dict(item))
                elif isinstance(raw, dict):
                    # Check if wrapper with list key (e.g. {"events": [...]})
                    found_list = False
                    for k, val in raw.items():
                        if isinstance(val, list) and val and isinstance(val[0], dict):
                            for i, item in enumerate(val):
                                if row_cap and i >= row_cap:
                                    break
                                records.append(flatten_dict(item))
                            found_list = True
                            break
                    if not found_list:
                        records.append(flatten_dict(raw))

            return pd.DataFrame(records)

        else:
            # Fallback: attempt CSV
            return pd.read_csv(path, nrows=row_cap)

    except Exception as e:
        raise ValueError(f"Failed to parse tabular file {path.name}: {e}") from e


def read_sql_to_df(
    connection_string: str,
    table_name: str | None = None,
    query: str | None = None,
    row_cap: int = 1000,
) -> pd.DataFrame:
    """Read a table or read-only SELECT query from a SQL database.
    Rejects data-modifying statements (DROP, INSERT, UPDATE, DELETE, ALTER).
    """
    if query:
        q_upper = query.strip().upper()
        # Enforce read-only constraint
        forbidden_keywords = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "REPLACE"]
        for kw in forbidden_keywords:
            if kw in q_upper:
                raise ValueError(f"Write operation '{kw}' is not allowed in read-only SQL connection.")
        if not q_upper.startswith("SELECT") and not q_upper.startswith("WITH"):
            raise ValueError("Only SELECT or WITH queries are allowed.")
        sql_to_run = f"SELECT * FROM ({query}) AS subq LIMIT {row_cap}"
    elif table_name:
        sql_to_run = f"SELECT * FROM {table_name} LIMIT {row_cap}"
    else:
        raise ValueError("Either table_name or query must be provided.")

    engine = create_engine(connection_string, execution_options={"readonly": True})
    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql_to_run), conn)
    return df
