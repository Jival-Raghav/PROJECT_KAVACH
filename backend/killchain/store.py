"""DuckDB access to an ingested run."""
from __future__ import annotations

import json
from pathlib import Path

import duckdb

from killchain.atomic import write_json_atomic

# A firewall does not write this many lines in one microsecond: the clock has stopped.
STALL_MIN_LINES = 1000
STALLS_FILE = "clock_stalls.json"


def sql_str(value: str) -> str:
    """Single-quoted SQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def _connect() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute("SET memory_limit='4GB'")
    con.execute("SET TimeZone='UTC'")
    return con


def list_parts(run_dir: Path) -> list[Path]:
    """The run's finished Parquet parts, sorted by name (never `*.tmp`)."""
    return sorted((Path(run_dir) / "events").glob("part-*.parquet"))


def _parts(run_dir: Path, parts: list[Path] | None = None) -> str:
    if parts is not None:
        return "[" + ", ".join(sql_str(str(p)) for p in parts) + "]"
    return sql_str(str(Path(run_dir) / "events" / "*.parquet"))


def find_clock_stalls(run_dir: Path, min_lines: int = STALL_MIN_LINES,
                      parts: list[Path] | None = None) -> list[dict]:
    """Timestamps shared by at least `min_lines` lines: the log's clock stopped there."""
    con = _connect()
    rows = con.execute(f"""
        SELECT epoch_us(CAST(ts AS TIMESTAMPTZ)), count(*), min(line_no), max(line_no)
        FROM read_parquet({_parts(run_dir, parts)})
        GROUP BY 1 HAVING count(*) >= {int(min_lines)} ORDER BY 3""").fetchall()
    con.close()
    return [{"ts_us": ts, "lines": n, "first_line": first, "last_line": last}
            for ts, n, first, last in rows]


def write_clock_stalls(run_dir: Path, parts: list[Path] | None = None) -> list[dict]:
    stalls = find_clock_stalls(run_dir, parts=parts)
    write_json_atomic(Path(run_dir) / STALLS_FILE, stalls)
    return stalls


def load_clock_stalls(run_dir: Path, parts: list[Path] | None = None) -> list[dict]:
    """Stalls recorded at ingest; computed now for a run ingested before stalls were tracked."""
    path = Path(run_dir) / STALLS_FILE
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return write_clock_stalls(run_dir, parts)


def open_events(run_dir: Path, parts: list[Path] | None = None) -> duckdb.DuckDBPyConnection:
    """In-memory DuckDB connection over the run's Parquet parts.

    `events` leaves out clock-stalled lines, so rate, window and baseline logic never sees them.
    `events_all` keeps every parsed line.
    """
    stalls = load_clock_stalls(run_dir, parts)
    con = _connect()
    con.execute(f"CREATE VIEW events_all AS SELECT * REPLACE (CAST(ts AS TIMESTAMPTZ) AS ts) "
                f"FROM read_parquet({_parts(run_dir, parts)})")
    frozen = ", ".join(str(int(s["ts_us"])) for s in stalls)
    keep = f"WHERE epoch_us(ts) NOT IN ({frozen})" if frozen else ""
    con.execute(f"CREATE VIEW events AS SELECT * FROM events_all {keep}")
    return con
