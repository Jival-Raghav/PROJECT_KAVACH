"""
backend/graph/paths.py — Attack Path Analysis to Crown Jewels.

Calculates the shortest and lowest-cost lateral movement and privilege escalation
paths from a compromised node to crown jewel resources or systems.
"""
from __future__ import annotations

from typing import Any
import networkx as nx


def find_attack_paths_to_crown_jewels(
    g: nx.DiGraph,
    source_node: str,
    top_n: int = 5,
    max_hops: int = 5,
) -> list[dict[str, Any]]:
    """
    Finds top-N lowest-cost attack paths from source_node to any crown jewel node.
    """
    if source_node not in g:
        candidates = [n for n in g.nodes if n.endswith(f":{source_node}") or n == source_node]
        if candidates:
            source_node = candidates[0]
        else:
            return []

    # Find all crown jewel nodes
    crown_nodes = [
        n for n, data in g.nodes(data=True)
        if data.get("is_crown", False) or data.get("sensitivity") == "crown"
    ]

    all_paths = []

    for target in crown_nodes:
        if target == source_node:
            continue
        try:
            # Find shortest paths weighted by traversal cost
            paths = list(nx.all_shortest_paths(g, source_node, target, weight="weight"))
            for p in paths:
                if len(p) - 1 <= max_hops:
                    cost = 0.0
                    hops_detail = []
                    for i in range(len(p) - 1):
                        u, v = p[i], p[i + 1]
                        edge_data = g.get_edge_data(u, v, default={})
                        cost += edge_data.get("weight", 1.0)
                        hops_detail.append({
                            "from_node": u,
                            "from_label": g.nodes[u].get("label", u),
                            "from_type": g.nodes[u].get("node_type", "unknown"),
                            "to_node": v,
                            "to_label": g.nodes[v].get("label", v),
                            "to_type": g.nodes[v].get("node_type", "unknown"),
                            "edge_type": edge_data.get("edge_type", "traversal"),
                            "cost": edge_data.get("weight", 1.0),
                        })

                    all_paths.append({
                        "source": source_node,
                        "target": target,
                        "target_name": g.nodes[target].get("label", target),
                        "target_type": g.nodes[target].get("node_type", "system"),
                        "total_cost": round(cost, 2),
                        "hop_count": len(p) - 1,
                        "nodes": p,
                        "hops": hops_detail,
                    })
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    # Sort by total_cost ascending (easiest / lowest resistance path first)
    all_paths.sort(key=lambda x: (x["total_cost"], x["hop_count"]))
    return all_paths[:top_n]
