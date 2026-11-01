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


def _low_parse(path, junk, good, gz=False):
    text = "junk line\n" * junk + "".join(fg_line(at(i)) + "\n" for i in range(good))
    if gz:
        with gzip.open(path, "wt") as fh:
            fh.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def test_progress_saved_before_first_part_on_low_parse_file(tmp_path, monkeypatch):
    import killchain.live as live

    p = _low_parse(tmp_path / "low.log", 60_000, 5)
    run = tmp_path / "run"
    saved = []
    real = live.save_state
    monkeypatch.setattr(live, "save_state", lambda d, s: (saved.append(dict(s)), real(d, s)))
    st = stream_to_parts(p, run, new_state(p), batch_size=200_000)
    early = [s for s in saved if s["parts"] == 0 and not s["ingest_done"]]
    assert early and early[0]["lines_read"] == 50_000 and early[0]["bytes_read"] > 0
    assert early[0]["next_offset"] == 0
    assert early[0]["checkpoint"] == {"lines_read": 0, "lines_parsed": 0, "lines_skipped": 0}
    assert st["parts"] == 1 and st["lines_parsed"] == 5 and st["lines_skipped"] == 60_000


def test_resume_after_progress_save_does_not_skip_or_double_count(tmp_path, monkeypatch):
    import killchain.live as live

    for gz in (False, True):
        p = _low_parse(tmp_path / f"low{gz}.log", 30, 25, gz=gz)
        run = tmp_path / f"run{gz}"
        monkeypatch.setattr(live, "PROGRESS_EVERY", 7)
        stop = threading.Event()
        real = live.save_state
        monkeypatch.setattr(live, "save_state", lambda d, s, real=real: (
            real(d, s), s["parts"] == 1 and s["lines_read"] > s["checkpoint"]["lines_read"]
            and stop.set()))
        st = new_state(p)
        stream_to_parts(p, run, st, batch_size=10, stop=stop)
        saved = read_state(run)
        assert saved["parts"] == 1 and saved["lines_read"] > saved["checkpoint"]["lines_read"]
        monkeypatch.setattr(live, "save_state", real)
        st = stream_to_parts(p, run, read_state(run), batch_size=10)
        assert st["ingest_done"] and st["parts"] == 3
        assert (st["lines_read"], st["lines_parsed"], st["lines_skipped"]) == (55, 25, 30)
        assert _line_nos(run) == list(range(31, 56))


def test_junk_file_raises_after_limit(tmp_path, monkeypatch):
    import pytest

    import killchain.live as live

    monkeypatch.setattr(live, "NO_PARSE_LIMIT", 50)
    p = _low_parse(tmp_path / "junk.log", 60, 0)
    with pytest.raises(ValueError, match="No FortiGate log lines found in the first 50 lines"):
        stream_to_parts(p, tmp_path / "run", new_state(p))
    # parsed lines before the limit keep it from tripping
    p2 = _low_parse(tmp_path / "ok.log", 0, 2)
    p2.write_text(p2.read_text() + "junk\n" * 60, encoding="utf-8")
    assert stream_to_parts(p2, tmp_path / "run2", new_state(p2))["lines_parsed"] == 2


def test_gz_resume_skip_honours_stop(tmp_path, monkeypatch):
    import killchain.live as live

    gz = _gz(tmp_path)
    st = new_state(gz)
    st["checkpoint"] = {"lines_read": 20, "lines_parsed": 20, "lines_skipped": 0}
    stop = threading.Event()
    skipped = []

    class Gz(gzip.GzipFile):
        def readline(self, *a):
            skipped.append(1)
            if len(skipped) == 3:
                stop.set()
            return super().readline(*a)

    monkeypatch.setattr(live.gzip, "GzipFile", Gz)
    out = stream_to_parts(gz, tmp_path / "run", st, batch_size=10, stop=stop)
    assert len(skipped) == 3
    assert out["parts"] == 0 and not out["ingest_done"]


def test_read_changes_keeps_last_entry_per_generation(tmp_path):
    import json

    from killchain.changes import read_changes

    rows = [{"generation": 1, "v": "a"}, {"generation": 2, "v": "b"},
            {"generation": 2, "v": "c"}, {"generation": 3, "v": "d"}]
    (tmp_path / "changes.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert [r["v"] for r in read_changes(tmp_path)] == ["a", "c", "d"]
    assert [r["v"] for r in read_changes(tmp_path, 1)] == ["c", "d"]
