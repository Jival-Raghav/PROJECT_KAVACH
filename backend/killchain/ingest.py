"""Stream a FortiGate log into Parquet parts without holding the file in memory (FR-1)."""
from __future__ import annotations

try:
    import resource
except ImportError:
    resource = None
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from killchain.models import IngestStats
from killchain.parse import FIELDS, parse_line
from killchain.store import STALLS_FILE, write_clock_stalls

_ARROW = {"int64": pa.int64(), "string": pa.string(), "timestamp": pa.timestamp("ns", tz="UTC")}
SCHEMA = pa.schema([(name, _ARROW[t]) for name, t in FIELDS])


def peak_rss_mb() -> float:
    if resource is not None:
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]
        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        # Declared types matter: the pseudo-handle is -1 and is pointer-sized on 64-bit Windows.
        current = ctypes.WinDLL("kernel32").GetCurrentProcess
        current.restype = wintypes.HANDLE
        info = ctypes.WinDLL("psapi").GetProcessMemoryInfo
        info.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
        info.restype = wintypes.BOOL
        if info(current(), ctypes.byref(pmc), pmc.cb):
            return pmc.PeakWorkingSetSize / (1024 * 1024)
    except (OSError, AttributeError):
        pass
    return 0.0  # unknown: reported as "not measured", never as a passing result


def _flush(batch: dict[str, list], path: Path) -> None:
    table = pa.Table.from_pydict(batch, schema=SCHEMA)
    pq.write_table(table, path, compression="zstd")


def _ingest_range(log_path: Path, start: int, end: int, first_line: int, events_dir: Path,
                  tag: int, batch_size: int, schema_path: Path | None = None) -> dict:
    """Parse the lines in bytes [start, end) into Parquet parts. `first_line` numbers the first one."""
    parse = parse_line
    if schema_path is not None:  # a log format learned by onboarding; FortiGate logs never come here
        from killchain.onboard import load_schema, make_parser

        parse = make_parser(load_schema(schema_path))
    names = [name for name, _ in FIELDS]
    batch: dict[str, list] = {n: [] for n in names}
    read = parsed = skipped = parts = pending = 0
    pos = start
    with open(log_path, "rb") as fh:
        fh.seek(start)
        for raw in fh:
            if pos >= end:
                break
            pos += len(raw)
            read += 1
            rec = None
            if raw.endswith(b"\n"):  # a final line without newline is a truncated write
                try:
                    rec = parse(raw.decode("utf-8"), first_line + read - 1)
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
                _flush(batch, events_dir / f"part-{tag:05d}-{parts:05d}.parquet")
                parts += 1
                batch = {n: [] for n in names}
                pending = 0
    if pending:
        _flush(batch, events_dir / f"part-{tag:05d}-{parts:05d}.parquet")
        parts += 1
    return {"read": read, "parsed": parsed, "skipped": skipped, "parts": parts,
            "pid": os.getpid(), "peak_rss_mb": peak_rss_mb()}


def _line_aligned_ranges(log_path: Path, size: int, chunk_bytes: int) -> list[tuple[int, int]]:
    """Byte ranges of about `chunk_bytes`, each ending just after a newline."""
    starts = [0]
    with open(log_path, "rb") as fh:
        for offset in range(chunk_bytes, size, chunk_bytes):
            if offset <= starts[-1]:
                continue
            fh.seek(offset - 1)
            fh.readline()
            if starts[-1] < fh.tell() < size:
                starts.append(fh.tell())
    return list(zip(starts, starts[1:] + [size]))


def _count_newlines(log_path: Path, start: int, end: int) -> int:
    count = 0
    with open(log_path, "rb") as fh:
        fh.seek(start)
        while (left := end - fh.tell()) > 0:
            block = fh.read(min(left, 8 * 1024 * 1024))
            if not block:
                break
            count += block.count(b"\n")
    return count


def _ingest_parallel(log_path: Path, events_dir: Path, ranges: list[tuple[int, int]],
                     workers: int, batch_size: int, schema_path: Path | None = None) -> list[dict]:
    # spawn everywhere: forking a process that has loaded DuckDB or Arrow threads is unsafe.
    with mp.get_context("spawn").Pool(workers) as pool:
        counts = pool.starmap(_count_newlines, [(log_path, s, e) for s, e in ranges], chunksize=1)
        first_lines = [1 + sum(counts[:i]) for i in range(len(ranges))]
        # Many small ranges, handed out as workers free up, so a slow region cannot idle the others.
        return pool.starmap(_ingest_range,
                            [(log_path, s, e, first, events_dir, tag, batch_size, schema_path)
                             for tag, ((s, e), first) in enumerate(zip(ranges, first_lines))],
                            chunksize=1)


def ingest_log(log_path: Path, out_dir: Path, batch_size: int = 200_000, workers: int = 1,
               chunk_bytes: int = 256 * 1024 * 1024, schema_path: Path | None = None) -> IngestStats:
    start = time.perf_counter()
    events_dir = Path(out_dir) / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    for old in events_dir.glob("part-*.parquet"):
        old.unlink()
    (Path(out_dir) / STALLS_FILE).unlink(missing_ok=True)

    size = Path(log_path).stat().st_size
    ranges = _line_aligned_ranges(log_path, size, chunk_bytes)
    parallel = workers > 1 and len(ranges) > 1
    if parallel:
        results = _ingest_parallel(log_path, events_dir, ranges, workers, batch_size, schema_path)
    else:
        results = [_ingest_range(log_path, 0, size, 1, events_dir, 0, batch_size, schema_path)]
    worker_peaks: dict[int, float] = {}
    for r in results:
        worker_peaks[r["pid"]] = max(worker_peaks.get(r["pid"], 0.0), r["peak_rss_mb"])
    peak_while_reading = peak_rss_mb() + (sum(worker_peaks.values()) if parallel else 0.0)

    parts = sum(r["parts"] for r in results)
    stalled = sum(s["lines"] for s in write_clock_stalls(out_dir)) if parts else 0
    return IngestStats(lines_read=sum(r["read"] for r in results),
                       lines_parsed=sum(r["parsed"] for r in results),
                       lines_skipped=sum(r["skipped"] for r in results),
                       lines_stalled=stalled, parts=parts,
                       seconds=round(time.perf_counter() - start, 2),
                       peak_rss_mb=round(max(peak_while_reading, peak_rss_mb()), 1),
                       workers=workers if parallel else 1)
