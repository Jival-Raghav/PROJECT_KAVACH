"""Link detections into incidents (FR-4) and count merged alerts (B-3).

Two detections join the same incident when either
  * strong link – they share an attacker-side entity (an external IP in any role, a user,
    or a domain) and their time intervals are at most `strong_gap_hours` apart; or
  * actor link  – they share an internal source host and are at most `actor_gap_hours` apart
    (one compromised host doing several things in a short burst); or
  * pivot link  – an internal host is a victim (`dst_ip`) of the earlier detection and the
    actor (`src_ip`) of a later one that starts within `pivot_gap_hours` of the earlier's end.
A shared internal victim alone never links detections.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from killchain.models import Detection, Incident

_STRONG_ROLES = ("user", "domain")


def _is_internal(ip: str, prefixes: tuple[str, ...]) -> bool:
    return ip.startswith(prefixes)


def _strong_keys(d: Detection, prefixes: tuple[str, ...]) -> set[str]:
    keys = {f"ip:{ip}" for role in ("src_ip", "dst_ip") for ip in d.entities.get(role, [])
            if not _is_internal(ip, prefixes)}
    keys |= {f"{role}:{v.lower()}" for role in _STRONG_ROLES for v in d.entities.get(role, [])}
    return keys


def _interval_gap(a: Detection, b: Detection) -> timedelta:
    if a.last_seen < b.first_seen:
        return b.first_seen - a.last_seen
    if b.last_seen < a.first_seen:
        return a.first_seen - b.last_seen
    return timedelta(0)


def correlate(detections: list[Detection], strong_gap_hours: float = 72,
              pivot_gap_hours: float = 24, actor_gap_hours: float = 6,
              internal_prefixes: tuple[str, ...] = ("10.",)) -> list[Incident]:
    dets = sorted(detections, key=lambda d: (d.first_seen, d.detection_id))
    parent = list(range(len(dets)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    strong_gap = timedelta(hours=strong_gap_hours)
    pivot_gap = timedelta(hours=pivot_gap_hours)
    actor_gap = timedelta(hours=actor_gap_hours)
    keys = [_strong_keys(d, internal_prefixes) for d in dets]

    def internal(d: Detection, role: str) -> set[str]:
        return {ip for ip in d.entities.get(role, []) if _is_internal(ip, internal_prefixes)}

    actors = [internal(d, "src_ip") for d in dets]
    victims = [internal(d, "dst_ip") for d in dets]
    for i, a in enumerate(dets):
        for j in range(i + 1, len(dets)):
            b = dets[j]
            if keys[i] & keys[j] and _interval_gap(a, b) <= strong_gap:
                union(i, j)
            elif actors[i] & actors[j] and _interval_gap(a, b) <= actor_gap:
                union(i, j)
    # Pivot: link a later detection acting FROM host H only to the most recent successful
    # (not blocked) detection that landed ON H — never to every attacker that probed H.
    for j, b in enumerate(dets):
        candidates = [i for i, a in enumerate(dets)
                      if i != j and a.outcome != "blocked" and victims[i] & actors[j]
                      and a.first_seen <= b.first_seen
                      and b.first_seen - a.last_seen <= pivot_gap]
        if candidates:
            union(max(candidates, key=lambda i: (dets[i].first_seen, dets[i].detection_id)), j)

    groups: dict[int, list[Detection]] = {}
    for i, d in enumerate(dets):
        groups.setdefault(find(i), []).append(d)
    incidents = [_build(members, internal_prefixes) for members in groups.values()]
    incidents.sort(key=lambda inc: (inc.first_seen, inc.detections[0].detection_id))
    for n, inc in enumerate(incidents, start=1):
        inc.incident_id = n
    return incidents


def _attacker(members: list[Detection], prefixes: tuple[str, ...]) -> str:
    """Name the attacker: external source, else external destination (C2), else user/host."""
    for role in ("src_ip", "dst_ip"):
        for d in members:
            for ip in d.entities.get(role, []):
                if not _is_internal(ip, prefixes):
                    return ip
    for role in ("user", "src_ip"):
        for d in members:
            if d.entities.get(role):
                return d.entities[role][0]
    return "unknown actor"


def _build(members: list[Detection], prefixes: tuple[str, ...]) -> Incident:
    members = sorted(members, key=lambda d: (d.first_seen, d.detection_id))
    entities: dict[str, list[str]] = {}
    for d in members:
        for role, vals in d.entities.items():
            entities.setdefault(role, [])
            entities[role] = sorted(set(entities[role]) | set(vals))
    by_stage = sorted(members, key=lambda d: (d.technique.stage_index, d.first_seen))
    tactics: list[str] = []
    stages: list[str] = []
    for d in by_stage:
        if d.technique.tactic not in tactics:
            tactics.append(d.technique.tactic)
        if d.technique.stage not in stages:
            stages.append(d.technique.stage)
    top = by_stage[-1]
    first: datetime = min(d.first_seen for d in members)
    last: datetime = max(d.last_seen for d in members)
    return Incident(
        incident_id=0, title=f"{_attacker(members, prefixes)}: {top.title}", detections=members,
        first_seen=first, last_seen=last, entities=entities, tactics=tactics, stages=stages,
        raw_alert_count=sum(d.event_count for d in members),
    )
