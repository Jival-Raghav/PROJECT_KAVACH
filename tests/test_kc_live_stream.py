import gzip
import shutil
import threading

from tests.kc_fixture import at, fg_line, write_log

from killchain.live import new_state, read_state, save_state, stream_to_parts
from killchain.store import list_parts, open_events


def _log(tmp_path, n=25):
    return write_log(tmp_path / "x.log", [fg_line(at(i), srcip=f"10.0.0.{i % 200}") for i in range(n)])


def _gz(tmp_path, n=25):
    src = _log(tmp_path, n)
    gz = tmp_path / "x.log.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write(src.read_text())
    return gz


def _line_nos(run):
    con = open_events(run, parts=list_parts(run))
    return [r[0] for r in con.execute("select line_no from events_all order by line_no").fetchall()]


def _resume_check(path, run):
    stop = threading.Event()
    st = new_state(path)
    save_state(run, st)

    def on_part(s):
        stop.set()

    st = stream_to_parts(path, run, st, batch_size=10, stop=stop, on_part=on_part)
    assert st["parts"] == 1 and st["ingest_done"] is False
    st = stream_to_parts(path, run, read_state(run), batch_size=10)
    assert st["parts"] == 3 and st["ingest_done"] is True
    assert _line_nos(run) == list(range(1, 26))
    return st


def test_stream_raw_writes_parts_and_checkpoint(tmp_path):
    path = _log(tmp_path)
    run = tmp_path / "run"
    st = stream_to_parts(path, run, new_state(path), batch_size=10)
    assert st["parts"] == 3 and st["lines_parsed"] == 25
    assert st["next_offset"] == path.stat().st_size and st["ingest_done"]
    assert st["bytes_read"] == st["bytes_total"]
    assert read_state(run)["parts"] == 3
    n = open_events(run, parts=list_parts(run)).execute("select count(*) from events_all").fetchone()[0]
    assert n == 25


def test_stream_resume_matches_uninterrupted(tmp_path):
    _resume_check(_log(tmp_path), tmp_path / "run")


def test_stream_gz_and_resume(tmp_path):
    gz = _gz(tmp_path)
    st = _resume_check(gz, tmp_path / "run")
    assert st["gz"] is True


def test_stream_counts_malformed_and_truncated_last_line(tmp_path):
    lines = [fg_line(at(i)) for i in range(5)]
    lines.insert(2, "junk")
    p = tmp_path / "m.log"
    p.write_text("".join(x + "\n" for x in lines) + fg_line(at(9)), encoding="utf-8")
    st = stream_to_parts(p, tmp_path / "run", new_state(p), batch_size=10)
    assert st["lines_skipped"] == 2 and st["lines_read"] == 7 and st["lines_parsed"] == 5


def test_no_partial_parts_visible(tmp_path):
    path = _log(tmp_path)
    run = tmp_path / "run"
    stream_to_parts(path, run, new_state(path), batch_size=10)
    files = sorted((run / "events").iterdir())
    assert not [f for f in files if f.name.endswith(".tmp")]
    assert files == list_parts(run)
    shutil.rmtree(run)
