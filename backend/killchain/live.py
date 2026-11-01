"""Live mode: resumable streaming reader and the job that re-analyses as parts arrive."""
from __future__ import annotations

import contextlib
import gzip
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from killchain.atomic import write_json_atomic
from killchain.changes import append_change, diff_cycle
from killchain.ingest import SCHEMA, peak_rss_mb
from killchain.parse import FIELDS, parse_line
from killchain.pipeline import analyse_run, load_run
from killchain.store import list_parts, write_clock_stalls

STATE_FILE = "live_state.json"
ZIP_MAGIC = b"PK\x03\x04"
NO_PARSE_LIMIT = 100_000  # lines read with nothing parsed before giving up on a file
PROGRESS_EVERY = 50_000  # save read counters at least this often, even between parts
HEARTBEAT_SECONDS = 5.0  # how often a live job refreshes heartbeat_at
STALE_SECONDS = 60.0  # a heartbeat older than this means the owner is gone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_zip(path: Path) -> bool:
    with open(path, "rb") as fh:
        return fh.read(4) == ZIP_MAGIC


def owner_alive(state: dict) -> bool:
    """True when `state` is processing and its owner process is alive with a fresh heartbeat."""
    if state.get("status") != "processing":
        return False
    pid, beat = state.get("owner_pid"), state.get("heartbeat_at")
    if not pid or not beat:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # alive, owned by another user
        pass
    except (OSError, ValueError):
        return False
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(beat)).total_seconds()
    except (TypeError, ValueError):
        return False
    return age <= STALE_SECONDS


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
            "finished_at": None, "error": None, "owner_pid": None, "heartbeat_at": None,
            # Counters as of the last written part: what a resume restarts from.
            "checkpoint": {"lines_read": 0, "lines_parsed": 0, "lines_skipped": 0}}


def _write_part(batch: dict[str, list], events_dir: Path, part: int) -> None:
    table = pa.Table.from_pydict(batch, schema=SCHEMA)
    final = events_dir / f"part-{part:05d}.parquet"
    tmp = events_dir / f"part-{part:05d}.parquet.tmp"
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, final)


def stream_to_parts(path: Path, run_dir: Path, state: dict, *, batch_size: int = 200_000,
                    stop: threading.Event | None = None,
                    on_part: Callable[[dict], None] | None = None,
                    lock: threading.Lock | None = None) -> dict:
    """Append Parquet parts from `path`, checkpointing `state` after every part.

    `lock`, when given, is held around every mutation and save of `state` (never around a
    Parquet write), so another thread sharing `state` can mutate and save it safely.
    """
    run_dir = Path(run_dir)
    guard = lock if lock is not None else contextlib.nullcontext()
    events_dir = run_dir / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    if state.get("ingest_done"):
        return state
    names = [n for n, _ in FIELDS]
    gz = state["gz"]
    # Resume from the last written part. lines_* may run ahead of it (progress saves), so
    # they are only shown, never resumed from; older states have no checkpoint and agree.
    ck = state.get("checkpoint") or {k: state[k] for k in
                                     ("lines_read", "lines_parsed", "lines_skipped")}
    raw_file = open(path, "rb")
    try:
        if gz:
            fh = gzip.GzipFile(fileobj=raw_file)
            for _ in range(ck["lines_read"]):
                if stop is not None and stop.is_set():
                    return state
                if not fh.readline():
                    break
            offset = 0
        else:
            raw_file.seek(state["next_offset"])
            fh = raw_file
            offset = state["next_offset"]
        read, parsed, skipped = ck["lines_read"], ck["lines_parsed"], ck["lines_skipped"]
        batch: dict[str, list] = {n: [] for n in names}
        pending = 0
        last_save = read

        def counters() -> None:  # caller holds guard
            state.update(lines_read=read, lines_parsed=parsed, lines_skipped=skipped,
                         bytes_read=raw_file.tell() if gz else offset, heartbeat_at=_now())

        def checkpoint() -> None:
            nonlocal batch, pending
            wrote = bool(pending)
            if wrote:
                _write_part(batch, events_dir, state["parts"])
                batch = {n: [] for n in names}
                pending = 0
            with guard:
                if wrote:
                    state["parts"] += 1
                counters()
                state["checkpoint"] = {"lines_read": read, "lines_parsed": parsed,
                                       "lines_skipped": skipped}
                if not gz:
                    state["next_offset"] = offset
                save_state(run_dir, state)
            if on_part:
                on_part(state)

        def progress() -> None:
            """Save the read counters only; parts, next_offset and checkpoint stay put."""
            with guard:
                counters()
                save_state(run_dir, state)

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
                if parsed == 0 and read >= NO_PARSE_LIMIT:
                    raise ValueError(f"No FortiGate log lines found in the first "
                                     f"{NO_PARSE_LIMIT:,} lines of {path}")
            else:
                parsed += 1
                for n in names:
                    batch[n].append(rec[n])
                pending += 1
                if pending >= batch_size:
                    checkpoint()
                    last_save = read
                    if stop is not None and stop.is_set():
                        return state
                    continue
            if read - last_save >= PROGRESS_EVERY:
                progress()
                last_save = read
        if stop is not None and stop.is_set():
            return state
        if pending:
            _write_part(batch, events_dir, state["parts"])
        with guard:
            if pending:
                state["parts"] += 1
            state.update(lines_read=read, lines_parsed=parsed, lines_skipped=skipped,
                         ingest_done=True, bytes_read=state["bytes_total"], heartbeat_at=_now(),
                         checkpoint={"lines_read": read, "lines_parsed": parsed,
                                     "lines_skipped": skipped})
            if not gz:
                state["next_offset"] = offset
            save_state(run_dir, state)
        return state
    finally:
        raw_file.close()


REGISTRY_FILE = "incident_registry.json"
_INGEST_KEYS = ("lines_read", "lines_parsed", "lines_skipped", "parts", "bytes_read",
                "bytes_total")


class LiveJob:
    """Stream `path` into Parquet parts in a reader thread and re-analyse as parts arrive.

    The reader thread and the job thread share `state`; every mutation and save of it holds
    `self._lock`. Cycles run only in the job thread, so they never overlap.
    """

    def __init__(self, run_dir: Path, path: Path, rules_dir: Path, *,
                 assets_path: Path | None = None, batch_size: int = 200_000,
                 poll_seconds: float = 0.5,
                 on_cycle: Callable[[dict], None] | None = None) -> None:
        self.run_dir = Path(run_dir)
        self.path = Path(path).resolve()
        self.rules_dir = Path(rules_dir)
        self.assets_path = assets_path
        self.batch_size = batch_size
        self.poll_seconds = poll_seconds
        self.on_cycle = on_cycle
        existing = read_state(self.run_dir)
        if existing is not None and existing.get("path") != str(self.path):
            raise ValueError(f"Run {self.run_dir.name} was started on {existing.get('path')}")
        self.state: dict = existing if existing is not None else new_state(self.path)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._reader_exc: BaseException | None = None
        self._reader_t0: float | None = None
        self._reader_t1: float | None = None

    # -- control ---------------------------------------------------------------------------
    def start(self) -> None:
        """Run the job in a daemon thread; errors are only recorded in `state`.

        The processing state is on disk before this returns, so a caller listing runs
        right after sees the new run as live and owned.
        """
        self._claim()
        self._thread = threading.Thread(target=self._run_quietly, name="kc-live-job",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Ask the reader and the cycle loop to finish after the current part / cycle."""
        self._stop.set()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def _claim(self) -> None:
        self._update(status="processing", error=None, finished_at=None,
                     owner_pid=os.getpid(), heartbeat_at=_now())

    def _beat(self, done: threading.Event) -> None:
        while not done.wait(HEARTBEAT_SECONDS):
            self._update(heartbeat_at=_now())

    def _run_quietly(self) -> None:
        with contextlib.suppress(BaseException):  # already recorded as status="error"
            self.run()

    # -- job -------------------------------------------------------------------------------
    def run(self) -> dict:
        """Block until the reader has finished and every part is analysed (or stop/error)."""
        self._claim()
        done = threading.Event()
        beat = threading.Thread(target=self._beat, args=(done,), name="kc-live-beat",
                                daemon=True)
        beat.start()
        try:
            return self._run()
        finally:
            done.set()
            beat.join()

    def _run(self) -> dict:
        reader = threading.Thread(target=self._read, name="kc-live-reader", daemon=True)
        covered = 0
        try:
            reader.start()
            while True:
                # Sample the reader before listing parts: if it was already finished, the
                # listing below is final and the loop may end once it is covered.
                reader_done = not reader.is_alive()
                if self._reader_exc is not None:
                    raise self._reader_exc
                if self._stop.is_set():
                    break
                n = len(list_parts(self.run_dir))
                if n > covered:
                    covered = self._cycle()
                    continue
                if reader_done:
                    break
                self._stop.wait(self.poll_seconds)
            reader.join()
            if self._reader_exc is not None:
                raise self._reader_exc
        except BaseException as exc:
            self._stop.set()
            if reader.is_alive():
                reader.join()
            self._update(status="error", error=str(exc))
            raise
        with self._lock:
            complete = (self.state["ingest_done"]
                        and covered >= len(list_parts(self.run_dir)))
            if complete:
                self.state.update(status="complete", finished_at=_now())
            else:
                self.state["status"] = "stopped"
            save_state(self.run_dir, self.state)
            return dict(self.state)

    def _read(self) -> None:
        self._reader_t0 = time.perf_counter()
        try:
            stream_to_parts(self.path, self.run_dir, self.state, batch_size=self.batch_size,
                            stop=self._stop, lock=self._lock)
        except BaseException as exc:  # surfaced by the job thread
            self._reader_exc = exc
        finally:
            self._reader_t1 = time.perf_counter()

    def _reader_elapsed(self) -> float:
        if self._reader_t0 is None:
            return 0.0
        end = self._reader_t1 if self._reader_t1 is not None else time.perf_counter()
        return round(end - self._reader_t0, 2)

    def _update(self, **fields) -> None:
        with self._lock:
            self.state.update(fields)
            save_state(self.run_dir, self.state)

    def _cycle(self) -> int:
        """Analyse every part written so far; return how many parts it covered."""
        t = time.perf_counter()
        parts = list_parts(self.run_dir)
        with self._lock:
            ingest = {k: self.state[k] for k in _INGEST_KEYS}
            generation = self.state["generation"] + 1
        total = ingest["bytes_total"]
        pct = ingest["bytes_read"] / total if total else 1.0
        elapsed = self._reader_elapsed()
        ingest.update(seconds=elapsed, peak_rss_mb=round(peak_rss_mb(), 1))

        write_clock_stalls(self.run_dir, parts)
        prev = load_run(self.run_dir)
        meta = analyse_run(self.run_dir, self.rules_dir, assets_path=self.assets_path,
                           parts=parts, registry_path=self.run_dir / REGISTRY_FILE,
                           seconds={"ingest": elapsed},
                           meta_extra={"log_path": str(self.path), "ingest": ingest})
        cur = load_run(self.run_dir)
        # The generation survives a resume, so it doubles as the cycle number.
        entry = diff_cycle(prev, cur, meta.get("renumber") or {}, cycle=generation,
                           generation=generation, pct=pct)
        append_change(self.run_dir, entry)
        self._update(generation=generation, cycle_seconds=round(time.perf_counter() - t, 2),
                     last_cycle_at=_now(), heartbeat_at=_now())
        if self.on_cycle is not None:
            self.on_cycle(entry)
        return len(parts)
