"""
backend/graph/blast.py — Blast Radius Analytics for Identity Knowledge Graph.

Computes:
- Reachable systems and resources from an account or identity within k hops.
- Sensitivity-weighted blast radius score (0-100).
- Reachable crown jewel assets.
- Peer-relative blast percentile.
"""
from __future__ import annotations

from typing import Any
import networkx as nx

SENSITIVITY_WEIGHTS = {
    "crown": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 1.0,
}


def compute_blast_radius(
    g: nx.DiGraph,
    start_node: str,
    max_depth: int = 4,
) -> dict[str, Any]:
    """
    Computes blast radius and reachable assets from start_node (account or identity).
    Returns score (0-100), reachable_systems, reachable_resources, crown_jewels, and path stats.
    """
    if start_node not in g:
        # Fallback if prefix was omitted (e.g. 'USR00173' instead of 'account:USR00173')
        candidates = [n for n in g.nodes if n.endswith(f":{start_node}") or n == start_node]
        if candidates:
            start_node = candidates[0]
        else:
            return {
                "node_id": start_node,
                "blast_score": 0.0,
                "reachable_nodes_count": 0,
                "reachable_systems": [],
                "reachable_resources": [],
                "crown_jewels": [],
                "details_by_sensitivity": {"crown": 0, "high": 0, "medium": 0, "low": 0},
            }

    # Breadth-first / single-source shortest path up to cutoff
    reachable_nodes = nx.single_source_shortest_path_length(g, start_node, cutoff=max_depth)

    reachable_systems = []
    reachable_resources = []
    crown_jewels = []
    sensitivity_counts = {"crown": 0, "high": 0, "medium": 0, "low": 0}
    weighted_score = 0.0

    # Total possible weight in the whole graph for normalization
    total_graph_weight = 0.0
    for node, data in g.nodes(data=True):
        ntype = data.get("node_type")
        if ntype in ("system", "resource"):
            sens = data.get("sensitivity", "medium").lower()
            w = SENSITIVITY_WEIGHTS.get(sens, 2.0)
            total_graph_weight += w

    for node, depth in reachable_nodes.items():
        data = g.nodes[node]
        ntype = data.get("node_type")
        sens = data.get("sensitivity", "medium").lower()
        is_crown = data.get("is_crown", False) or sens == "crown"

        if ntype == "system":
            reachable_systems.append({
                "node_id": node,
                "name": data.get("system_name", data.get("label", node)),
                "sensitivity": sens,
                "is_crown": is_crown,
                "hops": depth,
            })
            w = SENSITIVITY_WEIGHTS.get(sens, 2.0)
            weighted_score += w
            sensitivity_counts[sens] = sensitivity_counts.get(sens, 0) + 1
            if is_crown:
                crown_jewels.append({
                    "node_id": node,
                    "name": data.get("system_name", data.get("label", node)),
                    "type": "system",
                    "hops": depth,
                })

        elif ntype == "resource":
            reachable_resources.append({
                "node_id": node,
                "name": data.get("resource_name", data.get("label", node)),
                "system": data.get("system", "unknown"),
                "sensitivity": sens,
                "is_crown": is_crown,
                "hops": depth,
            })
            w = SENSITIVITY_WEIGHTS.get(sens, 2.0)
            weighted_score += w
            sensitivity_counts[sens] = sensitivity_counts.get(sens, 0) + 1
            if is_crown:
                crown_jewels.append({
                    "node_id": node,
                    "name": data.get("resource_name", data.get("label", node)),
                    "system": data.get("system", "unknown"),
                    "type": "resource",
                    "hops": depth,
                })

    # Normalized blast score: 0 to 100
    if total_graph_weight > 0:
        blast_score = min(100.0, round((weighted_score / total_graph_weight) * 100.0, 1))
    else:
        blast_score = min(100.0, round(weighted_score * 5.0, 1))

    return {
        "node_id": start_node,
        "blast_score": blast_score,
        "reachable_nodes_count": len(reachable_nodes),
        "reachable_systems": reachable_systems,
        "reachable_resources": reachable_resources,
        "crown_jewels": crown_jewels,
        "details_by_sensitivity": sensitivity_counts,
    }
