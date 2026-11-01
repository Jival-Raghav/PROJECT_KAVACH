"""Parser for logs that mix several sources line by line (a SIEM export).

Each line is recognised by its own shape and translated into the same `events` columns as FortiGate,
so the rules and analysis run unchanged. Lines from sources Kavach does not use are skipped and
counted. Recognised: Palo Alto (PAN-OS CSV), Suricata eve.json alerts, Cisco ASA (VPN sessions and
denies), sshd logins, web access logs, Linux auditd commands, Kubernetes audit, AWS CloudTrail and
macOS Gatekeeper overrides.

Times follow the FortiGate convention used here: the device's wall clock, stored as if it were UTC.
Sources that log in UTC are shifted by KILLCHAIN_LOCAL_TZ (default +05:30). Syslog lines carry no
year, so the current year is used.
"""
from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timedelta, timezone

from killchain.parse import _INT_COLS, COLUMNS

_TZ = os.getenv("KILLCHAIN_LOCAL_TZ", "+05:30")
_OFFSET = timedelta(hours=int(_TZ[:3]), minutes=int(_TZ[0] + _TZ[4:6]))
_YEAR = datetime.now().year
_PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

_SSH = re.compile(r"^<\d+>1 (\S+) (\S+) sshd \d+ .*?\] (?:(Failed password) for (?:invalid user )?(\S+)"
                  r"|(Invalid user) (\S+)|(Accepted) \S+ for (\S+)) from ([\d.]+)")
_WEB = re.compile(r'^([\d.]+) - \S+ \[(\d+/\w+/\d+:\d+:\d+:\d+) [^\]]+\] "(\S+) (\S+) [^"]*" (\d+) (\S+) "[^"]*" "([^"]*)"')
_AUDIT_EXEC = re.compile(r'^type=(?:EXECVE|EX) msg=audit\((\d+)\.\d+:\d+\):.*?a2="([^"]*)"')
_ASA_VPN = re.compile(r"^(\w{3} +\d+ \d+:\d+:\d+) (\S+) %ASA-6-113039: Group <([^>]*)> User <([^>]*)> IP <([\d.]+)>")
_ASA_DENY = re.compile(r"^(\w{3} +\d+ \d+:\d+:\d+) (\S+) %ASA-4-106023: Deny (\w+) src (\w+):([\d.]+)/(\d+) dst (\w+):([\d.]+)/(\d+)")
_MAC_GK = re.compile(r"^(\w{3} +\d+ \d+:\d+:\d+) (\S+) syspolicyd\[\d+\]: Gatekeeper assessment: (\S+) DENIED .*overridden by user (\S+)")

_PAN_ZONE = {"trust": "lan", "untrust": "wan", "dmz": "dmz"}
_PAN_ACTION = {"allow": "accept", "deny": "deny", "drop": "deny", "reset-both": "deny", "alert": "detected"}
_ASA_ZONE = {"inside": "lan", "outside": "wan", "dmz": "dmz"}
_SURICATA_SEV = {1: "high", 2: "medium", 3: "low"}
_PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


def _ns(wall: datetime) -> int:
    return int(wall.replace(tzinfo=timezone.utc).timestamp()) * 10**9 + wall.microsecond * 1000


def _local(dt: datetime) -> datetime:
    """Wall clock in the local zone, without tzinfo."""
    if dt.tzinfo is None:
        return dt
    return (dt.astimezone(timezone.utc) + _OFFSET).replace(tzinfo=None)


def _syslog_time(text: str) -> datetime:
    return datetime.strptime(f"{_YEAR} {text}", "%Y %b %d %H:%M:%S")


def _role(ip: str | None) -> str | None:
    return None if not ip else ("lan" if _PRIVATE.match(ip) else "wan")


def _record(line_no: int, wall: datetime, source: str, **fields) -> dict:
    rec = dict.fromkeys(COLUMNS)
    rec["line_no"] = line_no
    rec["ts"] = _ns(wall)
    rec["logid"] = source
    for k, v in fields.items():
        if v is None or v == "":
            continue
        if k in _INT_COLS:
            try:
                rec[k] = int(v)
            except (TypeError, ValueError):
                continue
        else:
            rec[k] = str(v)[:500]
    return rec


def _panos(line: str, n: int) -> dict | None:
    row = next(csv.reader([line]))
    if len(row) < 31 or row[3] not in ("TRAFFIC", "THREAT"):
        return None
    wall = datetime.strptime(row[1], "%Y/%m/%d %H:%M:%S")
    common = dict(srcip=row[7], dstip=row[8], app=row[14], srcintfrole=_PAN_ZONE.get(row[16], row[16]),
                  dstintfrole=_PAN_ZONE.get(row[17], row[17]), srcintf=row[18], dstintf=row[19],
                  sessionid=row[22], srcport=row[24], dstport=row[25], proto=_PROTO.get(row[29]),
                  action=_PAN_ACTION.get(row[30], row[30]))
    if row[3] == "TRAFFIC":
        return _record(n, wall, "panos", type="traffic", subtype=row[4], sentbyte=row[31] if len(row) > 31 else None,
                       rcvdbyte=row[32] if len(row) > 32 else None, duration=row[35] if len(row) > 35 else None,
                       **common)
    return _record(n, wall, "panos", type="utm", subtype="ips" if row[4] == "vulnerability" else row[4],
                   url=row[31], attack=row[32], catdesc=row[33], severity=row[34],
                   dstcountry=row[39] if len(row) > 39 else None, **common)


def _json(line: str, n: int) -> dict | None:
    try:
        r = json.loads(line)
    except ValueError:
        return None
    if r.get("event_type") == "alert" and "flow_id" in r:  # Suricata eve.json
        a, f = r.get("alert") or {}, r.get("flow") or {}
        wall = _local(datetime.fromisoformat(r["timestamp"]))
        return _record(n, wall, "suricata", type="utm", subtype="ips", srcip=r.get("src_ip"),
                       srcport=r.get("src_port"), dstip=r.get("dest_ip"), dstport=r.get("dest_port"),
                       srcintfrole=_role(r.get("src_ip")), dstintfrole=_role(r.get("dest_ip")),
                       proto=_PROTO.get(str(r.get("proto", "")).lower()), app=r.get("app_proto"),
                       action="accept" if a.get("action") == "allowed" else "deny", attack=a.get("signature"),
                       attackid=a.get("signature_id"), catdesc=a.get("category"),
                       severity=_SURICATA_SEV.get(a.get("severity")), sentbyte=f.get("bytes_toserver"),
                       rcvdbyte=f.get("bytes_toclient"))
    if str(r.get("apiVersion", "")).startswith("audit.k8s.io"):
        obj = r.get("objectRef") or {}
        stamp = r.get("requestReceivedTimestamp") or r.get("stageTimestamp")
        wall = _local(datetime.fromisoformat(stamp.replace("Z", "+00:00")))
        msg = f"{obj.get('namespace', '')}/{obj.get('resource', '')}/{obj.get('name', '')}"
        if '"privileged":true' in line:
            msg += " privileged=true"
        return _record(n, wall, "k8s", type="host", subtype="k8s", user=(r.get("user") or {}).get("username"),
                       srcip=(r.get("sourceIPs") or [None])[0], method=r.get("verb"), url=r.get("requestURI"),
                       status=(r.get("responseStatus") or {}).get("code"), msg=msg)
    if "eventVersion" in r and "eventName" in r:  # AWS CloudTrail
        u = r.get("userIdentity") or {}
        wall = _local(datetime.fromisoformat(r["eventTime"].replace("Z", "+00:00")))
        user = u.get("userName") or (u.get("arn") or "").split("/")[-1] or u.get("type")
        return _record(n, wall, "cloudtrail", type="host", subtype="cloudtrail", logdesc=r.get("eventName"),
                       user=user, ui=u.get("type"), srcip=r.get("sourceIPAddress"), service=r.get("eventSource"),
                       status=r.get("errorCode") or "ok")
    return None


def parse_line(line: str, line_no: int) -> dict | None:
    """Same contract as parse.parse_line: a full record, or None for a line Kavach does not use."""
    line = line.rstrip("\r\n")
    try:
        c = line[:1]
        if c == "{":
            return _json(line, line_no)
        if line.startswith("1,") and (",TRAFFIC," in line[:60] or ",THREAT," in line[:60]):
            return _panos(line, line_no)
        if c == "<" and " sshd " in line[:120]:
            m = _SSH.match(line)
            if m:
                failed = m.group(3) or m.group(5)
                ip = m.group(9)
                return _record(line_no, _local(datetime.fromisoformat(m.group(1))), "sshd", type="host",
                               subtype="ssh", action="failed" if failed else "success", srcip=ip,
                               srcintfrole=_role(ip), hostname=m.group(2), user=m.group(4) or m.group(6) or m.group(8),
                               logdesc="SSH login failed" if failed else "SSH login successful")
            return None
        if c.isdigit() and " - " in line[:20]:
            m = _WEB.match(line)
            if m:
                ip = m.group(1)
                return _record(line_no, datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S"), "web", type="host",
                               subtype="http", srcip=ip, srcintfrole=_role(ip), method=m.group(3), url=m.group(4),
                               status=m.group(5), rcvdbyte=m.group(6) if m.group(6).isdigit() else None,
                               msg=m.group(7))
            return None
        if line.startswith("type=EX"):
            m = _AUDIT_EXEC.match(line)
            if m:
                wall = datetime.fromtimestamp(int(m.group(1)), timezone.utc).replace(tzinfo=None) + _OFFSET
                dst = re.search(r"/dev/tcp/([\d.]+)/(\d+)", m.group(2))
                return _record(line_no, wall, "auditd", type="host", subtype="exec", msg=m.group(2),
                               dstip=dst.group(1) if dst else None, dstport=dst.group(2) if dst else None)
            return None
        if "%ASA-" in line[:60]:
            m = _ASA_VPN.match(line)
            if m:
                return _record(line_no, _syslog_time(m.group(1)), "asa", type="event", subtype="vpn",
                               action="tunnel-up", logdesc="VPN session started", hostname=m.group(2),
                               user=m.group(4), srcip=m.group(5), srcintfrole="wan")
            m = _ASA_DENY.match(line)
            if m:
                return _record(line_no, _syslog_time(m.group(1)), "asa", type="traffic", subtype="forward",
                               action="deny", proto=_PROTO.get(m.group(3)), srcip=m.group(5), srcport=m.group(6),
                               srcintfrole=_ASA_ZONE.get(m.group(4), m.group(4)), dstip=m.group(8),
                               dstport=m.group(9), dstintfrole=_ASA_ZONE.get(m.group(7), m.group(7)))
            return None
        if "syspolicyd" in line[:80]:
            m = _MAC_GK.match(line)
            if m:
                return _record(line_no, _syslog_time(m.group(1)), "macos", type="host", subtype="endpoint",
                               hostname=m.group(2), logdesc="Gatekeeper block overridden", url=m.group(3),
                               user=m.group(4))
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
    return None


def looks_mixed(lines: list[str]) -> bool:
    """Several known sources, each on its own lines: a SIEM-style mixed export."""
    kinds = {rec["logid"] for i, ln in enumerate(lines, 1) if (rec := parse_line(ln, i))}
    return len(kinds) >= 2
