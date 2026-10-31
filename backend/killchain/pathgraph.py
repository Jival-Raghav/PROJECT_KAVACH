"""Incident timeline and attack-path graph of hosts, users and external actors (FR-5)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from killchain.models import Detection, Incident

DEVICE_TZ = "+05:30"  # FortiGate eventtime encodes the device's local wall clock
_MAX_ACTORS = 50
_MAX_TARGETS = 50


class TimelineStep(BaseModel):
    ts: str
    technique_id: str
    technique_name: str
    tactic: str
    stage: str
    description: str
    detection_id: str
    event_count: int
    outcome: str


class PathGraph(BaseModel):
    nodes: list[dict]
    edges: list[dict]


def format_ts(dt: datetime) -> str:
    """Device-local ISO timestamp (the log's own clock)."""
    return dt.replace(tzinfo=None).isoformat(timespec="seconds") + DEVICE_TZ


def build_timeline(inc: Incident) -> list[TimelineStep]:
    steps = []
    for d in sorted(inc.detections, key=lambda d: (d.first_seen, d.detection_id)):
        span = "" if d.first_seen == d.last_seen else f" until {format_ts(d.last_seen)}"
        steps.append(TimelineStep(
            ts=format_ts(d.first_seen), technique_id=d.technique.id,
            technique_name=d.technique.name, tactic=d.technique.tactic, stage=d.technique.stage,
            description=f"{d.summary}; outcome {d.outcome}{span}", detection_id=d.detection_id,
            event_count=d.event_count, outcome=d.outcome))
    return steps


def _ip_node(ip: str, prefixes: tuple[str, ...], firewall_ip: str) -> dict:
    if ip == firewall_ip:
        return {"id": f"firewall:{ip}", "label": f"Firewall {ip}", "kind": "firewall",
                "segment": None}
    if ip.startswith(prefixes):
        seg = ".".join(ip.split(".")[:3]) + ".0/24"
        return {"id": f"host:{ip}", "label": ip, "kind": "host", "segment": seg}
    return {"id": f"external_ip:{ip}", "label": ip, "kind": "external_ip", "segment": None}


def build_path(inc: Incident, firewall_ip: str = "10.10.99.1",
               internal_prefixes: tuple[str, ...] = ("10.",)) -> PathGraph:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(n: dict) -> str:
        nodes.setdefault(n["id"], n)
        return n["id"]

    def ip(v: str) -> str:
        return node(_ip_node(v, internal_prefixes, firewall_ip))

    def user(v: str) -> str:
        return node({"id": f"user:{v}", "label": v, "kind": "user", "segment": None})

    def edge(src: str, dst: str, d: Detection) -> None:
        edges.append({"source": src, "target": dst, "technique_id": d.technique.id,
                      "ts": format_ts(d.first_seen),
                      "label": f"{d.technique.id} {d.technique.name}"})

    for d in sorted(inc.detections, key=lambda d: (d.first_seen, d.detection_id)):
        e = d.entities
        actors = [ip(v) for v in e.get("src_ip", [])[:_MAX_ACTORS]]
        users = e.get("user", [])
        if users:
            for u in users:
                uid = user(u)
                for a in actors or []:
                    edge(a, uid, d)
                for acc in e.get("account", []):
                    edge(uid, user(acc), d)
                for t in e.get("dst_ip", [])[:_MAX_TARGETS]:
                    edge(uid, ip(t), d)
            continue
        if not actors:
            continue
        targets = [ip(t) for t in e.get("dst_ip", [])[:_MAX_TARGETS]]
        targets += [node({"id": f"domain:{v}", "label": v, "kind": "domain", "segment": None})
                    for v in e.get("domain", [])]
        for a in actors:
            for t in targets:
                if a != t:
                    edge(a, t, d)
    edges.sort(key=lambda x: x["ts"])
    return PathGraph(nodes=list(nodes.values()), edges=edges)
