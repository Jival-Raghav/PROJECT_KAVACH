"""DuckDB access to an ingested run."""
from __future__ import annotations

from pathlib import Path

import duckdb


def sql_str(value: str) -> str:
    """Single-quoted SQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def open_events(run_dir: Path) -> duckdb.DuckDBPyConnection:
    """In-memory DuckDB connection with a view `events` over the run's Parquet parts."""
    con = duckdb.connect()
    con.execute("SET memory_limit='4GB'")
    con.execute("SET TimeZone='UTC'")
    pattern = sql_str(str(Path(run_dir) / "events" / "*.parquet"))
    con.execute(f"CREATE VIEW events AS SELECT * REPLACE (CAST(ts AS TIMESTAMPTZ) AS ts) FROM read_parquet({pattern})")
    return con
