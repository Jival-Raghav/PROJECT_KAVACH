"""Live mode: resumable streaming reader (and, later, the analysis job) for local logs."""
from __future__ import annotations

import gzip
import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from killchain.atomic import write_json_atomic
from killchain.ingest import SCHEMA
from killchain.parse import FIELDS, parse_line

STATE_FILE = "live_state.json"


def read_state(run_dir: Path) -> dict | None:
    import json
    path = Path(run_dir) / STATE_FILE
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(run_dir: Path, state: dict) -> None:
    Path(run_dir).mkdir(parents=True, exist_ok=True)
    write_json_atomic(Path(run_dir) / STATE_FILE, state)


def new_state(path: Path) -> dict:
    path = Path(path).resolve()
    with open(path, "rb") as fh:
        gz = fh.read(2) == b"\x1f\x8b"
    size = path.stat().st_size
    return {"path": str(path), "status": "processing", "gz": gz, "parts": 0, "lines_read": 0,
            "lines_parsed": 0, "lines_skipped": 0, "next_offset": 0, "bytes_read": 0,
            "bytes_total": size, "ingest_done": False, "generation": 0, "cycle_seconds": None,
            "last_cycle_at": None, "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None, "error": None}


def _write_part(batch: dict[str, list], events_dir: Path, part: int) -> None:
    table = pa.Table.from_pydict(batch, schema=SCHEMA)
    final = events_dir / f"part-{part:05d}.parquet"
    tmp = events_dir / f"part-{part:05d}.parquet.tmp"
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, final)


def stream_to_parts(path: Path, run_dir: Path, state: dict, *, batch_size: int = 200_000,
                    stop: threading.Event | None = None,
                    on_part: Callable[[dict], None] | None = None) -> dict:
    """Append Parquet parts from `path`, checkpointing `state` after every part."""
    run_dir = Path(run_dir)
    events_dir = run_dir / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    if state.get("ingest_done"):
        return state
    names = [n for n, _ in FIELDS]
    gz = state["gz"]
    raw_file = open(path, "rb")
    try:
        if gz:
            fh = gzip.GzipFile(fileobj=raw_file)
            for _ in range(state["lines_read"]):
                if not fh.readline():
                    break
            offset = 0
        else:
            raw_file.seek(state["next_offset"])
            fh = raw_file
            offset = state["next_offset"]
        read, parsed, skipped = state["lines_read"], state["lines_parsed"], state["lines_skipped"]
        batch: dict[str, list] = {n: [] for n in names}
        pending = 0

        def checkpoint() -> None:
            nonlocal batch, pending
            if pending:
                _write_part(batch, events_dir, state["parts"])
                state["parts"] += 1
                batch = {n: [] for n in names}
                pending = 0
            state.update(lines_read=read, lines_parsed=parsed, lines_skipped=skipped)
            if not gz:
                state["next_offset"] = offset
            state["bytes_read"] = raw_file.tell() if gz else offset
            save_state(run_dir, state)
            if on_part:
                on_part(state)

        for raw in fh:
            if stop is not None and stop.is_set():
                return state
            read += 1
            offset += len(raw)
            rec = None
            if raw.endswith(b"\n"):  # a final line without newline is a truncated write
                try:
                    rec = parse_line(raw.decode("utf-8"), read)
                except UnicodeDecodeError:
                    rec = None
            if rec is None:
                skipped += 1
                continue
            parsed += 1
            for n in names:
                batch[n].append(rec[n])
            pending += 1
            if pending >= batch_size:
                checkpoint()
                if stop is not None and stop.is_set():
                    return state
        if stop is not None and stop.is_set():
            return state
        if pending:
            _write_part(batch, events_dir, state["parts"])
            state["parts"] += 1
        state.update(lines_read=read, lines_parsed=parsed, lines_skipped=skipped,
                     ingest_done=True, bytes_read=state["bytes_total"])
        if not gz:
            state["next_offset"] = offset
        save_state(run_dir, state)
        return state
    finally:
        raw_file.close()
