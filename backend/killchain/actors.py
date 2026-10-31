"""Link one actor across source IPs and accounts, using only proven activity.

Evidence is a successful admin or VPN login, a configuration change, or one account creating
another. Failed logins never link anything: they are password-spray noise with guessed names.
Actors are context only: they never create incidents or change risk scores.
"""
from __future__ import annotations

import networkx as nx

from killchain.anomaly import incident_entities
from killchain.models import Incident
from killchain.pathgraph import format_ts

MAX_USERS_PER_IP = 5  # an IP shared by more accounts is probably NAT or a gateway, not one actor

_EVIDENCE_SQL = """
    SELECT user, srcip, srccountry,
           CASE WHEN logdesc = 'Admin login successful' THEN 'admin_login'
                WHEN subtype = 'vpn' THEN 'vpn_login'
                ELSE 'config_change' END AS kind,
           count(*) AS events, min(ts) AS first_seen, max(ts) AS last_seen
    FROM events
    WHERE user IS NOT NULL AND user <> '' AND srcip IS NOT NULL AND (
          logdesc = 'Admin login successful'
       OR (subtype = 'vpn' AND action IN ('ssl-login', 'tunnel-up'))
       OR logdesc IN ('Attribute configured', 'Object attribute configured'))
    GROUP BY ALL ORDER BY first_seen, user, srcip"""

_CREATED_SQL = """
    SELECT user, regexp_extract(msg, 'system\\.admin (\\S+)', 1) AS created, min(ts) AS first_seen
    FROM events
    WHERE logdesc = 'Object attribute configured' AND msg LIKE 'Add system.admin%'
      AND user IS NOT NULL
    GROUP BY 1, 2 ORDER BY 3, 1, 2"""


def build_actors(con) -> list[dict]:
    evidence = [dict(zip(("user", "ip", "country", "kind", "events", "first_seen", "last_seen"), row))
                for row in con.execute(_EVIDENCE_SQL).fetchall()]
    created = con.execute(_CREATED_SQL).fetchall()

    users_per_ip: dict[str, set[str]] = {}
    for e in evidence:
        users_per_ip.setdefault(e["ip"], set()).add(e["user"].lower())
    shared = {ip for ip, users in users_per_ip.items() if len(users) > MAX_USERS_PER_IP}

    g = nx.Graph()
    names: dict[str, str] = {}  # lowercase account key -> name as written in the log
    for e in evidence:
        key = e["user"].lower()
        names.setdefault(key, e["user"])
        g.add_node(f"user:{key}")
        if e["ip"] not in shared:
            g.add_edge(f"user:{key}", f"ip:{e['ip']}")
    created_by: dict[str, list[dict]] = {}
    for creator, account, first_seen in created:
        if not account:
            continue
        names.setdefault(creator.lower(), creator)
        names.setdefault(account.lower(), account)
        g.add_edge(f"user:{creator.lower()}", f"user:{account.lower()}")
        created_by.setdefault(f"user:{creator.lower()}", []).append(
            {"creator": creator, "account": account, "ts": format_ts(first_seen)})

    actors = []
    for component in nx.connected_components(g):
        users = sorted(names[n[5:]] for n in component if n.startswith("user:"))
        ips = sorted(n[3:] for n in component if n.startswith("ip:"))
        keys = {u.lower() for u in users}
        rows = [e for e in evidence if e["user"].lower() in keys]
        countries = sorted({e["country"] for e in rows if e["country"]})
        actors.append({
            "users": users, "ips": ips, "countries": countries,
            "first_seen": format_ts(min(e["first_seen"] for e in rows)) if rows else None,
            "last_seen": format_ts(max(e["last_seen"] for e in rows)) if rows else None,
            "evidence": [{**e, "first_seen": format_ts(e["first_seen"]),
                          "last_seen": format_ts(e["last_seen"])} for e in rows],
            "accounts_created": [c for n in component for c in created_by.get(n, [])],
            "incident_ids": [],
        })
    actors.sort(key=lambda a: (-len(a["ips"]) - len(a["users"]), a["users"]))
    for number, actor in enumerate(actors, start=1):
        actor["actor_id"] = number
    return actors


def link_incidents(actors: list[dict], incidents: list[Incident]) -> dict[int, list[dict]]:
    """Mark each actor with its incidents; return incident id -> actors involved in it."""
    by_incident: dict[int, list[dict]] = {}
    lower = [({u.lower() for u in a["users"]} | set(a["ips"]), a) for a in actors]
    for inc in incidents:
        named = {v.lower() for v in incident_entities(inc)}
        for members, actor in lower:
            if {m.lower() for m in members} & named:
                actor["incident_ids"].append(inc.incident_id)
                by_incident.setdefault(inc.incident_id, []).append(actor)
    for actor in actors:
        actor["incident_ids"].sort()
    return by_incident
