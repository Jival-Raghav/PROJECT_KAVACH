"""Parse one FortiOS `key=value` log line into a flat, typed record."""
from __future__ import annotations

import json
import re

# (column, arrow type). Untyped columns are strings. `extra` holds unknown keys as JSON.
FIELDS: list[tuple[str, str]] = [
    ("line_no", "int64"), ("ts", "timestamp"),
    ("logid", "string"), ("type", "string"), ("subtype", "string"), ("level", "string"),
    ("action", "string"),
    ("srcip", "string"), ("srcport", "int64"), ("srcintf", "string"), ("srcintfrole", "string"),
    ("dstip", "string"), ("dstport", "int64"), ("dstintf", "string"), ("dstintfrole", "string"),
    ("proto", "int64"), ("service", "string"), ("policyid", "int64"), ("sessionid", "int64"),
    ("srccountry", "string"), ("dstcountry", "string"),
    ("sentbyte", "int64"), ("rcvdbyte", "int64"), ("duration", "int64"),
    ("app", "string"), ("appcat", "string"), ("apprisk", "string"),
    ("logdesc", "string"), ("msg", "string"), ("user", "string"), ("ui", "string"),
    ("method", "string"), ("status", "string"), ("reason", "string"),
    ("hostname", "string"), ("url", "string"), ("catdesc", "string"),
    ("attack", "string"), ("attackid", "int64"), ("severity", "string"), ("virus", "string"),
    ("crscore", "int64"),
    ("extra", "string"),
]
COLUMNS = [name for name, _ in FIELDS]
_INT_COLS = {name for name, t in FIELDS if t == "int64"}
_KNOWN = set(COLUMNS)
# Header keys that carry no information beyond `ts` / the single device.
_DROP = {"date", "time", "eventtime", "tz", "devname", "devid", "vd", "sentpkt", "rcvdpkt"}

_KV = re.compile(r'(?:^| )(\w+)=("(?:[^"\\]|\\.)*"|\S*)')


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def parse_line(line: str, line_no: int) -> dict | None:
    """Return a record with every column in COLUMNS, or None when the line is malformed."""
    if not line.startswith("date="):
        return None
    pairs = {k: (v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v)
             for k, v in _KV.findall(line.rstrip("\r\n"))}
    ts = _to_int(pairs.get("eventtime", ""))
    if ts is None:
        return None
    rec: dict = dict.fromkeys(COLUMNS)
    rec["line_no"] = line_no
    rec["ts"] = ts
    extra = {}
    for k, v in pairs.items():
        if k in _DROP:
            continue
        if k in _KNOWN:
            rec[k] = _to_int(v) if k in _INT_COLS else v
        else:
            extra[k] = v
    rec["extra"] = json.dumps(extra) if extra else None
    return rec
