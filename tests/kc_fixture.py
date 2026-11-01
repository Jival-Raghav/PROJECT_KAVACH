"""Test helpers: build synthetic FortiGate log lines and ingest them."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_IST = timezone(timedelta(hours=5, minutes=30))
_BASE = datetime(2026, 10, 23, 8, 0, 0, tzinfo=_IST)
_BARE = {"date", "time", "eventtime", "srcip", "dstip", "srcport", "dstport", "sessionid",
         "proto", "policyid", "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt", "duration",
         "attackid", "crscore"}


def at(minutes: float) -> datetime:
    """A local (+0530) timestamp `minutes` after the fixture base time."""
    return _BASE + timedelta(minutes=minutes)


def fg_line(when: datetime | None = None, **fields) -> str:
    """One FortiOS key=value line. Header fields are filled in; strings are quoted."""
    when = when or _BASE
    head = {
        "date": when.strftime("%Y-%m-%d"),
        "time": when.strftime("%H:%M:%S"),
        "eventtime": str(int(when.timestamp() * 1_000_000_000)),
        "tz": "+0530",
        "devname": "FGT60FTK00000000",
        "devid": "FGT60FTK00000000",
        "logid": "0000000013",
        "type": "traffic",
        "subtype": "forward",
        "level": "notice",
        "vd": "root",
    }
    head.update({k: str(v) for k, v in fields.items()})
    parts = []
    for k, v in head.items():
        parts.append(f"{k}={v}" if k in _BARE else f'{k}="{v}"')
    return " ".join(parts)


def write_log(path: Path, lines: list[str]) -> Path:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def ingest_lines(tmp_path: Path, lines: list[str]) -> Path:
    """Write `lines` to a log, ingest it, and return the run directory."""
    from killchain.ingest import ingest_log

    run_dir = tmp_path / "run"
    ingest_log(write_log(tmp_path / "fixture.log", lines), run_dir)
    return run_dir
