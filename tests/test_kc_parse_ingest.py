import json

from tests.kc_fixture import fg_line, write_log
from killchain.ingest import ingest_log
from killchain.parse import parse_line
from killchain.store import open_events


def test_parse_quoted_values_with_spaces_and_equals():
    line = ('date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" '
            'logid="0100032002" type="event" subtype="system" level="alert" '
            'msg="Administrator admin login failed from https(209.50.167.232) because x=y" '
            'url="/a?b=%3D1" srcip=209.50.167.232 dstport=443')
    r = parse_line(line, 7)
    assert r["msg"] == "Administrator admin login failed from https(209.50.167.232) because x=y"
    assert r["url"] == "/a?b=%3D1"
    assert r["srcip"] == "209.50.167.232" and r["dstport"] == 443 and r["line_no"] == 7
    assert r["ts"] == 1792745306564464000  # ns UTC


def test_parse_unknown_key_goes_to_extra():
    r = parse_line(fg_line(type="traffic", subtype="forward", foo="bar"), 1)
    assert json.loads(r["extra"]) == {"foo": "bar"}


def test_parse_rejects_malformed():
    assert parse_line("\x8b\x1f garbage", 1) is None
    assert parse_line('date=2026-10-23 time=08:48:26 type="traffic"', 2) is None  # no eventtime


def test_ingest_skips_bad_lines_and_batches(tmp_path):
    lines = [fg_line(type="traffic", subtype="forward", srcip=f"10.10.10.{i}") for i in range(25)]
    lines.insert(10, "binary\x00junk")
    stats = ingest_log(write_log(tmp_path / "x.log", lines), tmp_path / "run", batch_size=10)
    assert (stats.lines_read, stats.lines_parsed, stats.lines_skipped, stats.parts) == (26, 25, 1, 3)
    con = open_events(tmp_path / "run")
    assert con.execute("select count(*), max(line_no) from events").fetchone() == (25, 26)


def test_ingest_handles_truncated_last_line(tmp_path):
    p = tmp_path / "t.log"
    p.write_bytes((fg_line(type="traffic") + "\n").encode() + b'date=2026-10-30 time=08:48:25 type="tr')
    assert ingest_log(p, tmp_path / "run").lines_skipped == 1


def test_ingest_skips_invalid_utf8(tmp_path):
    p = tmp_path / "u.log"
    p.write_bytes((fg_line(type="traffic") + "\n").encode() + b"date=\xff\xfe\xfd eventtime=1\n")
    stats = ingest_log(p, tmp_path / "run")
    assert (stats.lines_parsed, stats.lines_skipped) == (1, 1)
