"""Parallel ingest must produce exactly what a serial read produces."""
import duckdb
import pytest

from killchain.ingest import _line_aligned_ranges, ingest_log
from tests.kc_fixture import fg_line


def _rows(run_dir):
    con = duckdb.connect()
    rows = con.execute(f"SELECT * FROM read_parquet('{run_dir / 'events' / '*.parquet'}') "
                       "ORDER BY line_no").fetchall()
    con.close()
    return rows


def _log(path, ending):
    lines = [fg_line(type="traffic", srcip=f"10.10.10.{i % 200}", dstport=i).encode() for i in range(300)]
    lines[50] = b"\xff\xfe invalid bytes"
    lines[120] = b"not a firewall line"
    path.write_bytes(b"\n".join(lines) + ending)
    return path


@pytest.mark.parametrize("ending", [b"\n", b"\ntruncated final line"], ids=["newline", "truncated"])
def test_parallel_matches_serial(tmp_path, ending):
    log = _log(tmp_path / "x.log", ending)
    serial = ingest_log(log, tmp_path / "serial", batch_size=40)
    parallel = ingest_log(log, tmp_path / "parallel", batch_size=40, workers=2, chunk_bytes=2000)
    assert parallel.workers == 2 and serial.workers == 1
    assert (parallel.lines_read, parallel.lines_parsed, parallel.lines_skipped) == (
        serial.lines_read, serial.lines_parsed, serial.lines_skipped)
    assert _rows(tmp_path / "parallel") == _rows(tmp_path / "serial")


def test_ranges_cover_the_file_on_line_boundaries(tmp_path):
    log = tmp_path / "r.log"
    log.write_bytes(b"short\n" + b"x" * 5000 + b"\n" + b"y\n" * 100)
    size = log.stat().st_size
    ranges = _line_aligned_ranges(log, size, 64)
    data = log.read_bytes()
    assert ranges[0][0] == 0 and ranges[-1][1] == size
    assert all(a[1] == b[0] for a, b in zip(ranges, ranges[1:]))
    assert all(data[s - 1:s] == b"\n" for s, _ in ranges[1:])


def test_small_file_stays_serial(tmp_path):
    log = _log(tmp_path / "s.log", b"\n")
    assert ingest_log(log, tmp_path / "run", workers=6).workers == 1
