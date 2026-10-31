"""What the attacker could reach next (FR-6).

Footholds come from the incident (internal hosts the attacker acted from or got onto, and the
firewall itself when an admin account was abused). Reach is computed on a network graph built
from *observed* accepted internal connections, reusing Kavach's blast-radius BFS, plus hosts on
the same segment, plus every segment when the firewall is controlled.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Literal

import networkx as nx
import yaml
from pydantic import BaseModel

from graph.blast import compute_blast_radius
from killchain.models import Incident

_RANK = {"crown": 0, "high": 1, "medium": 2, "low": 3}
_BASIS_RANK = {"admin_control": 0, "observed": 1, "same_segment": 2}
_ADMIN_TECHNIQUES = {"T1136.001", "T1098", "T1070", "T1562.001", "T1562.004"}
_ACCOUNT_TECHNIQUES = {"T1078", "T1110"}
_ACTOR_TACTICS = {"command-and-control", "discovery"}
_VICTIM_TACTICS = {"initial-access", "persistence", "lateral-movement", "execution", "exfiltration"}


class ReachTarget(BaseModel):
    node: str
    label: str
    segment: str
    sensitivity: str
    hops: int
    basis: Literal["observed", "same_segment", "admin_control"]


class ReachResult(BaseModel):
    incident_id: int
    footholds: list[str]
    targets: list[ReachTarget]
    summary: str


def load_assets(path: Path | None = None) -> dict:
    if path is None:
        from config import get_settings

        path = Path(get_settings().KILLCHAIN_ASSETS_PATH)
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def segmenter(assets: dict):
    """Build an `ip -> segment dict | None` lookup from `config/assets.yaml`.

    Shared with `pathgraph.build_path` so a host gets the same segment name (e.g. "DMZ
    servers") everywhere it is drawn, not just in the blast-radius graph.
    """
    nets = [(ipaddress.ip_network(s["cidr"]), s) for s in assets["segments"]]

    def seg(ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((s for net, s in nets if addr in net), None)

    return seg


def _internal_sql(col: str, assets: dict) -> str:
    """SQL predicate: `col` falls in one of the asset segments (octet-aligned prefixes)."""
    parts = []
    for s in assets["segments"]:
        net = ipaddress.ip_network(s["cidr"])
        octets = net.prefixlen // 8
        if net.prefixlen % 8 or octets == 0:
            return f"{col} IS NOT NULL"  # non-octet CIDR: filter in Python instead
        prefix = ".".join(str(net.network_address).split(".")[:octets]) + "."
        parts.append(f"starts_with({col}, '{prefix}')")
    return "(" + " OR ".join(parts) + ")"


def build_network_graph(con, assets: dict) -> nx.DiGraph:
    seg = segmenter(assets)
    src_in, dst_in = _internal_sql("srcip", assets), _internal_sql("dstip", assets)
    g = nx.DiGraph()
    g.add_node("system:firewall", node_type="system", label="Firewall", system_name="Firewall",
               sensitivity="crown", is_crown=True, segment="Management")
    for s in assets["segments"]:
        sid = f"segment:{s['cidr']}"
        g.add_node(sid, node_type="segment", label=s["name"], sensitivity=s["sensitivity"],
                   segment=s["name"], cidr=s["cidr"], hosts=0)
        g.add_edge("system:firewall", sid, basis="admin_control", weight=1.0)
    hosts = con.execute(f"""
        SELECT DISTINCT ip FROM (SELECT srcip AS ip FROM events WHERE {src_in}
                                 UNION ALL SELECT dstip FROM events WHERE {dst_in})""").fetchall()
    for (ip,) in hosts:
        s = seg(ip)
        if s is None or ip == assets.get("firewall_mgmt_ip"):
            continue
        g.add_node(f"system:{ip}", node_type="system", label=ip, system_name=ip,
                   sensitivity=s["sensitivity"], is_crown=s["sensitivity"] == "crown",
                   segment=s["name"])
        g.nodes[f"segment:{s['cidr']}"]["hosts"] += 1
    flows = con.execute(f"""
        SELECT srcip, dstip, list(DISTINCT dstport ORDER BY dstport) FROM events
        WHERE type = 'traffic' AND action = 'accept' AND {src_in} AND {dst_in}
        GROUP BY ALL""").fetchall()
    for src, dst, ports in flows:
        a, b = f"system:{src}", f"system:{dst}"
        if a in g and b in g and a != b:
            g.add_edge(a, b, basis="observed", ports=list(ports)[:20], weight=1.0)
    return g


def _footholds(inc: Incident, g: nx.DiGraph, firewall_ip: str) -> tuple[list[str], bool]:
    hosts: list[str] = []
    firewall = False
    for d in inc.detections:
        tid, tactic = d.technique.id, d.technique.tactic
        if tid in _ADMIN_TECHNIQUES or (tid in _ACCOUNT_TECHNIQUES and d.entities.get("user")):
            firewall = True
        if d.outcome != "blocked" or tactic in _ACTOR_TACTICS:
            hosts += [ip for ip in d.entities.get("src_ip", []) if f"system:{ip}" in g]
        if d.outcome != "blocked" and tactic in _VICTIM_TACTICS:
            hosts += [ip for ip in d.entities.get("dst_ip", []) if f"system:{ip}" in g]
    hosts = [h for h in dict.fromkeys(hosts) if h != firewall_ip]
    return hosts, firewall


def next_reach(inc: Incident, g: nx.DiGraph, assets: dict, max_depth: int = 2) -> ReachResult:
    fw_ip = assets.get("firewall_mgmt_ip", "")
    hosts, firewall = _footholds(inc, g, fw_ip)
    targets: dict[str, ReachTarget] = {}

    def add(t: ReachTarget) -> None:
        cur = targets.get(t.node)
        if cur is None or (_BASIS_RANK[t.basis], t.hops) < (_BASIS_RANK[cur.basis], cur.hops):
            targets[t.node] = t

    if firewall:
        for sid in g.successors("system:firewall"):
            n = g.nodes[sid]
            add(ReachTarget(node=sid, label=f"{n['label']} ({n['cidr']}, {n['hosts']} hosts)",
                            segment=n["segment"], sensitivity=n["sensitivity"], hops=1,
                            basis="admin_control"))
    footset = {f"system:{h}" for h in hosts}
    for h in hosts:
        start = f"system:{h}"
        blast = compute_blast_radius(g, start, max_depth=max_depth)
        for s in blast["reachable_systems"]:
            if s["node_id"] in footset or s["node_id"] == "system:firewall":
                continue
            n = g.nodes[s["node_id"]]
            add(ReachTarget(node=s["node_id"], label=n["label"], segment=n["segment"],
                            sensitivity=n["sensitivity"], hops=s["hops"], basis="observed"))
        my_seg = g.nodes[start]["segment"]
        for node, n in g.nodes(data=True):
            if (n.get("node_type") == "system" and node not in footset
                    and node != "system:firewall" and n.get("segment") == my_seg):
                add(ReachTarget(node=node, label=n["label"], segment=n["segment"],
                                sensitivity=n["sensitivity"], hops=1, basis="same_segment"))
    ordered = sorted(targets.values(), key=lambda t: (_RANK.get(t.sensitivity, 9),
                                                      _BASIS_RANK[t.basis], t.hops, t.label))
    footholds = (["firewall"] if firewall else []) + hosts
    return ReachResult(incident_id=inc.incident_id, footholds=footholds, targets=ordered,
                       summary=_summary(footholds, ordered, hosts, firewall, g))


def _summary(footholds, targets, hosts, firewall, g) -> str:
    if not footholds:
        return "No foothold: every observed step was blocked, so nothing new is reachable."
    parts = []
    if firewall:
        segs = [g.nodes[s] for s in g.successors("system:firewall")]
        total = sum(s["hosts"] for s in segs)
        top = ", ".join(s["label"] for s in sorted(segs, key=lambda s: _RANK[s["sensitivity"]])
                        if s["sensitivity"] in ("crown", "high"))
        parts.append(f"Admin control of the firewall: can change policy for {len(segs)} segments "
                     f"({total} hosts), including {top or 'all segments'}.")
    hosts_t = [t for t in targets if t.basis != "admin_control"]
    if hosts:
        obs = sum(t.basis == "observed" for t in hosts_t)
        same = sum(t.basis == "same_segment" for t in hosts_t)
        best = hosts_t[0] if hosts_t else None
        tail = f"; most sensitive: {best.segment} ({best.sensitivity})" if best else ""
        parts.append(f"From {len(hosts)} compromised host(s), {len(hosts_t)} hosts are reachable: "
                     f"{obs} via observed connections, {same} on the same segment{tail}.")
    return " ".join(parts)
