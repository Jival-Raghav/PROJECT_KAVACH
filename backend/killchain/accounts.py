"""Audit of accounts proven active in the log: service, shared and person accounts.

Only actors' proven activity counts. Names seen only in failed logins are password-spray guesses,
so they are not accounts. Account types are inferred from names, which is a hint and not a fact.
Findings are context only: they never create incidents or change risk scores.
"""
from __future__ import annotations

import re

from killchain.pathgraph import format_ts

_SERVICE_NAME = re.compile(r"(^svc|svc$|svc[_.-]|service|backup|^bot|[_.-]bot$|^api[_.-]|automation)", re.I)
_SHARED_NAME = re.compile(r"(_team$|^team[_.-]|shared|generic)", re.I)
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}

_LIFECYCLE_SQL = """
    SELECT regexp_extract(msg, 'system\\.admin (\\S+)', 1) AS account,
           min(ts) FILTER (WHERE msg LIKE 'Add %') AS created,
           min(ts) FILTER (WHERE msg LIKE 'Delete %') AS deleted
    FROM events
    WHERE logdesc = 'Object attribute configured' AND regexp_matches(msg, '^(Add|Delete) system\\.admin ')
    GROUP BY 1"""


def account_type(name: str) -> str:
    if _SERVICE_NAME.search(name):
        return "service"
    if _SHARED_NAME.search(name):
        return "shared"
    return "person"


def _finding(code: str, severity: str, text: str) -> dict:
    return {"code": code, "severity": severity, "text": text}


def _findings(name: str, kind: str, rows: list[dict], life: tuple | None) -> list[dict]:
    out = []
    vpn_ips = {r["ip"] for r in rows if r["kind"] == "vpn_login"}
    admin_ips = {r["ip"] for r in rows if r["kind"] == "admin_login"}
    change_ips = {r["ip"] for r in rows if r["kind"] == "config_change"}
    countries = {r["country"] for r in rows if r["kind"] == "vpn_login" and r["country"]}
    if kind == "service" and admin_ips:
        out.append(_finding("service_interactive_login", "critical",
                            f"Service-style account logged in to the firewall admin interface "
                            f"from {', '.join(sorted(admin_ips))}."))
    if life and life[0] and life[1]:
        minutes = (life[1] - life[0]).total_seconds() / 60
        out.append(_finding("short_lived_admin", "critical",
                            f"Admin account created {format_ts(life[0])} and deleted "
                            f"{minutes:.0f} minutes later."))
    if admin_ips and not vpn_ips:
        out.append(_finding("admin_without_history", "high",
                            "Admin login with no other proven activity by this account."))
    if vpn_ips and admin_ips - vpn_ips:
        out.append(_finding("admin_from_new_ip", "high",
                            f"Admin login from {', '.join(sorted(admin_ips - vpn_ips))}, "
                            "not an IP this account uses for VPN."))
    if vpn_ips and change_ips - vpn_ips:
        out.append(_finding("change_from_new_ip", "high",
                            f"Firewall changes from {', '.join(sorted(change_ips - vpn_ips))}, "
                            "not an IP this account uses for VPN."))
    if len(countries) > 1:
        out.append(_finding("vpn_multiple_countries", "high",
                            f"VPN use from {', '.join(sorted(countries))}."))
    if kind == "shared":
        out.append(_finding("shared_account", "medium",
                            "The name suggests a shared account, so activity cannot be tied to one person."))
    return out


def audit_accounts(con, actors: list[dict]) -> list[dict]:
    lifecycle = {str(a).lower(): (c, d) for a, c, d in con.execute(_LIFECYCLE_SQL).fetchall() if a}
    rows = []
    for actor in actors:
        for name in actor["users"]:
            evidence = [e for e in actor["evidence"] if e["user"].lower() == name.lower()]
            kind = account_type(name)
            findings = _findings(name, kind, evidence, lifecycle.get(name.lower()))
            findings.sort(key=lambda f: _SEVERITY_ORDER[f["severity"]])
            rows.append({"account": name, "type": kind,
                         "ips": sorted({e["ip"] for e in evidence}),
                         "vpn_logins": sum(e["events"] for e in evidence if e["kind"] == "vpn_login"),
                         "admin_logins": sum(e["events"] for e in evidence if e["kind"] == "admin_login"),
                         "config_changes": sum(e["events"] for e in evidence if e["kind"] == "config_change"),
                         "findings": findings, "incident_ids": list(actor["incident_ids"])})
    rows.sort(key=lambda r: (_SEVERITY_ORDER[r["findings"][0]["severity"]] if r["findings"] else 9,
                             -len(r["findings"]), r["account"].lower()))
    return rows
