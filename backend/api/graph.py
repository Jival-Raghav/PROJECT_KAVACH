"""
backend/api/graph.py — FastAPI router for Identity Knowledge Graph, Blast Radius, and What-If Analysis.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from graph.build import build_identity_graph
from graph.blast import compute_blast_radius
from graph.paths import find_attack_paths_to_crown_jewels
from graph.whatif import simulate_whatif_revoke
from graph.toxic import detect_toxic_combinations, find_unused_entitlements
from ingest.legacy_adapter import load_legacy_as_canonical

router = APIRouter(prefix="/api/graph", tags=["Knowledge Graph"])

# Cached graph singleton for fast queries
_CACHED_BUNDLE = None
_CACHED_GRAPH = None


def get_or_build_graph():
    global _CACHED_BUNDLE, _CACHED_GRAPH
    if _CACHED_GRAPH is None:
        _CACHED_BUNDLE = load_legacy_as_canonical()
        _CACHED_GRAPH = build_identity_graph(_CACHED_BUNDLE)
    return _CACHED_BUNDLE, _CACHED_GRAPH


class SimulateCompromiseRequest(BaseModel):
    account_id: str
    max_depth: int = Field(default=4, ge=1, le=8)


class WhatIfRevokeRequest(BaseModel):
    revocations: list[dict[str, str]]  # [{"account_id": "...", "entitlement": "..."}]
    replay_days: int = Field(default=60, ge=1, le=365)


@router.get("")
def get_graph_subgraph(
    focus: str | None = Query(None, description="Center node (e.g. account ID or identity ID)"),
    depth: int = Query(3, ge=1, le=5),
) -> dict[str, Any]:
    """
    Returns graph topology (nodes and links) for D3 visualization.
    If focus is given, returns the k-hop ego network; otherwise returns top connected component.
    """
    bundle, g = get_or_build_graph()

    target_nodes = set()
    if focus:
        start_node = focus
        if start_node not in g:
            matches = [n for n in g.nodes if n.endswith(f":{focus}") or n == focus]
            if matches:
                start_node = matches[0]

        if start_node in g:
            # Undirected view for ego network neighborhood
            undirected = g.to_undirected()
            import networkx as nx
            lengths = nx.single_source_shortest_path_length(undirected, start_node, cutoff=depth)
            target_nodes = set(lengths.keys())

    if not target_nodes:
        # Return top 150 nodes prioritized by crown jewels, admin accounts, and identities
        priority_nodes = []
        for n, data in g.nodes(data=True):
            score = 0
            if data.get("is_crown"):
                score += 50
            if data.get("privilege_level") == "admin":
                score += 30
            if data.get("node_type") == "identity":
                score += 10
            priority_nodes.append((score, n))
        priority_nodes.sort(key=lambda x: x[0], reverse=True)
        target_nodes = {n for _, n in priority_nodes[:120]}

    sub = g.subgraph(target_nodes)

    nodes = []
    for n in sub.nodes:
        d = g.nodes[n]
        nodes.append({
            "id": n,
            "label": d.get("label", n),
            "node_type": d.get("node_type", "unknown"),
            "system": d.get("system", d.get("system_name", "")),
            "sensitivity": d.get("sensitivity", "medium"),
            "is_crown": d.get("is_crown", False),
            "privilege_level": d.get("privilege_level"),
            "department": d.get("department"),
            "status": d.get("status"),
        })

    links = []
    for u, v, data in sub.edges(data=True):
        links.append({
            "source": u,
            "target": v,
            "edge_type": data.get("edge_type", "relates"),
            "weight": data.get("weight", 1.0),
        })

    return {
        "status": "success",
        "total_graph_nodes": g.number_of_nodes(),
        "total_graph_edges": g.number_of_edges(),
        "subgraph_nodes": len(nodes),
        "subgraph_edges": len(links),
        "nodes": nodes,
        "links": links,
    }


@router.post("/simulate-compromise")
def simulate_compromise(req: SimulateCompromiseRequest) -> dict[str, Any]:
    """
    Simulates identity/account compromise, returns reachable set, crown jewels, and attack paths.
    """
    bundle, g = get_or_build_graph()
    node_id = req.account_id
    if node_id not in g:
        matches = [n for n in g.nodes if n.endswith(f":{req.account_id}") or n == req.account_id]
        if matches:
            node_id = matches[0]

    blast = compute_blast_radius(g, node_id, max_depth=req.max_depth)
    paths = find_attack_paths_to_crown_jewels(g, node_id, top_n=5, max_hops=req.max_depth)

    return {
        "status": "success",
        "account_id": req.account_id,
        "resolved_node": node_id,
        "blast": blast,
        "attack_paths": paths,
    }


@router.post("/whatif")
def whatif_analysis(req: WhatIfRevokeRequest) -> dict[str, Any]:
    """
    Simulates revoking specific entitlements and measures risk delta vs business friction.
    """
    bundle, g = get_or_build_graph()
    res = simulate_whatif_revoke(bundle, g, req.revocations, replay_days=req.replay_days)
    return res


@router.get("/toxic-combinations")
def get_toxic_combinations() -> dict[str, Any]:
    """
    Identifies Multi-Hop SoD and toxic entitlement combinations held across the graph.
    """
    bundle, g = get_or_build_graph()
    toxic = detect_toxic_combinations(bundle, g)
    unused = find_unused_entitlements(bundle)
    return {
        "status": "success",
        "toxic_count": len(toxic),
        "toxic_findings": toxic,
        "unused_entitlements_count": len(unused),
        "unused_entitlements": unused[:30],
    }
