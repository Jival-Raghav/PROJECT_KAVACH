"""Stream a FortiGate log into Parquet parts without holding the file in memory (FR-1)."""
from __future__ import annotations

try:
    import resource
except ImportError:
    resource = None
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


def _flush(batch: dict[str, list], out: Path, part: int) -> None:
    table = pa.Table.from_pydict(batch, schema=SCHEMA)
    pq.write_table(table, out / f"part-{part:05d}.parquet", compression="zstd")


def ingest_log(log_path: Path, out_dir: Path, batch_size: int = 200_000) -> IngestStats:
    start = time.perf_counter()
    events_dir = Path(out_dir) / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    for old in events_dir.glob("part-*.parquet"):
        old.unlink()
    (Path(out_dir) / STALLS_FILE).unlink(missing_ok=True)

    names = [name for name, _ in FIELDS]
    batch: dict[str, list] = {n: [] for n in names}
    read = parsed = skipped = parts = 0
    pending = 0
    with open(log_path, "rb") as fh:
        for raw in fh:
            read += 1
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
                _flush(batch, events_dir, parts)
                parts += 1
                batch = {n: [] for n in names}
                pending = 0
    if pending:
        _flush(batch, events_dir, parts)
        parts += 1
    stalled = sum(s["lines"] for s in write_clock_stalls(out_dir)) if parts else 0
    return IngestStats(lines_read=read, lines_parsed=parsed, lines_skipped=skipped,
                       lines_stalled=stalled, parts=parts,
                       seconds=round(time.perf_counter() - start, 2), peak_rss_mb=round(peak_rss_mb(), 1))
