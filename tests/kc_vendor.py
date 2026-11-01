"""A made-up second firewall format ("Acme NGFW", JSON lines) for testing the learned-schema parser.

FortiGate events are rewritten in Acme's own field names and words, so the same attacks can be
run through both parsers and the results compared.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from killchain.parse import parse_line

# FortiGate column -> Acme field name
FIELDS = {
    "srcip": "src", "dstip": "dst", "srcport": "sport", "dstport": "dport", "proto": "ipproto",
    "action": "verdict", "srcintfrole": "zone_in", "dstintfrole": "zone_out", "type": "category",
    "subtype": "module", "logdesc": "event", "user": "account", "attack": "signature",
    "url": "uri", "hostname": "host", "virus": "malware", "msg": "message", "srccountry": "geo",
    "sentbyte": "bytes_out", "rcvdbyte": "bytes_in", "service": "app_proto",
}
# FortiGate value -> Acme word, per column
WORDS = {
    "action": {"accept": "allow", "deny": "drop", "dropped": "blocked", "passthrough": "permit",
               "blocked": "blocked-file", "detected": "alert-only"},
    "srcintfrole": {"wan": "outside", "lan": "inside", "dmz": "dmz"},
    "dstintfrole": {"wan": "outside", "lan": "inside", "dmz": "dmz"},
    "type": {"traffic": "flow", "utm": "threat", "event": "system"},
}

SCHEMA = {
    "format": "json",
    "columns": None,
    "timestamp": {"field": "time", "kind": "iso"},
    "fields": {acme: col for col, acme in FIELDS.items()},
    "values": {col: {acme: fg for fg, acme in table.items()} for col, table in WORDS.items()},
    "review": {"unmapped_log_fields": ["device"], "how_mapped": {}, "warnings": [], "rejected": [],
               "columns_not_found": []},
    "approved": True,
}


def to_acme(fortigate_line: str) -> str | None:
    """One FortiGate line as an Acme NGFW JSON line, or None if it does not parse."""
    rec = parse_line(fortigate_line, 1)
    if rec is None:
        return None
    ts = datetime.fromtimestamp(rec["ts"] / 1e9, UTC).strftime("%Y-%m-%d %H:%M:%S")
    out: dict = {"time": ts, "device": "acme-edge-01"}
    for col, acme in FIELDS.items():
        v = rec.get(col)
        if v is None or v == "":
            continue
        out[acme] = WORDS.get(col, {}).get(v, v)
    return json.dumps(out, separators=(",", ":"))
