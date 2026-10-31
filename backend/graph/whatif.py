"""
backend/graph/whatif.py — What-If Revoke Simulation & Historical Event Replay.

Simulates the removal of entitlements from accounts:
1. Recomputes blast radius and attack paths before vs after.
2. Replays historical events to quantify business breakage.
3. Classifies each revoke proposal as 'safe', 'review', or 'risky'.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import networkx as nx
from core.models import CanonicalBundle
from graph.blast import compute_blast_radius
from graph.paths import find_attack_paths_to_crown_jewels


def simulate_whatif_revoke(
    bundle: CanonicalBundle,
    g: nx.DiGraph,
    revocations: list[dict[str, str]],  # [{"account_id": ..., "entitlement": ...}]
    replay_days: int = 60,
) -> dict[str, Any]:
    """
    Simulates revoking specific entitlements and measures risk delta vs business friction.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=replay_days)

    # 1. Measure Initial State for Affected Accounts
    affected_accounts = list({r["account_id"] for r in revocations if "account_id" in r})
    initial_blast_scores = {}
    initial_paths = {}
    for acc in affected_accounts:
        acc_node = f"account:{acc}"
        initial_blast_scores[acc] = compute_blast_radius(g, acc_node)["blast_score"]
        initial_paths[acc] = len(find_attack_paths_to_crown_jewels(g, acc_node))

    # 2. Historical Replay: check how many events relied on these entitlements/systems
    events_by_account_system: dict[tuple[str, str], int] = {}
    for ev in bundle.events:
        try:
            if isinstance(ev.timestamp, str):
                ts = datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00"))
            else:
                ts = ev.timestamp if ev.timestamp.tzinfo else ev.timestamp.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                key = (ev.user_key, ev.system or "")
                events_by_account_system[key] = events_by_account_system.get(key, 0) + 1
        except Exception:
            key = (ev.user_key, ev.system or "")
            events_by_account_system[key] = events_by_account_system.get(key, 0) + 1

    # 3. Create Graph Clone with Revoked Edges Removed
    g_modified = g.copy()
    revocations_classified = []

    for rev in revocations:
        acc_id = rev["account_id"]
        ent_name = rev["entitlement"]
        acc_node = f"account:{acc_id}"

        # Find matching entitlement node
        matching_ent_nodes = [
            n for n in g_modified.successors(acc_node)
            if n.startswith("entitlement:") and ent_name.lower() in n.lower()
        ] if acc_node in g_modified else []

        # Find system associated
        system_name = "unknown"
        for ent in bundle.entitlements:
            if ent.account_id == acc_id and ent.entitlement.lower() == ent_name.lower():
                system_name = ent.system
                break

        # Replay event count for this account and system
        blocked_count = events_by_account_system.get((acc_id, system_name), 0)

        # Classification
        if blocked_count == 0:
            classification = "safe"
            impact_desc = "No recorded business operations in the last 60 days. Zero user disruption."
        elif blocked_count < 10:
            classification = "review"
            impact_desc = f"{blocked_count} historical actions impacted in '{system_name}'. Manager review suggested."
        else:
            classification = "risky"
            impact_desc = f"Heavy operational usage ({blocked_count} actions in last 60d). Disruption expected."

        # Remove edges from cloned graph
        for ent_node in matching_ent_nodes:
            if g_modified.has_edge(acc_node, ent_node):
                g_modified.remove_edge(acc_node, ent_node)

        revocations_classified.append({
            "account_id": acc_id,
            "entitlement": ent_name,
            "system": system_name,
            "blocked_events_count": blocked_count,
            "classification": classification,
            "impact_summary": impact_desc,
        })

    # 4. Measure Post-Revocation State
    post_blast_scores = {}
    post_paths = {}
    for acc in affected_accounts:
        acc_node = f"account:{acc}"
        post_blast_scores[acc] = compute_blast_radius(g_modified, acc_node)["blast_score"]
        post_paths[acc] = len(find_attack_paths_to_crown_jewels(g_modified, acc_node))

    # Aggregate summaries
    total_pre_blast = sum(initial_blast_scores.values())
    total_post_blast = sum(post_blast_scores.values())
    total_pre_paths = sum(initial_paths.values())
    total_post_paths = sum(post_paths.values())

    blast_reduction_pct = (
        round(((total_pre_blast - total_post_blast) / max(total_pre_blast, 0.001)) * 100.0, 1)
        if total_pre_blast > 0 else 0.0
    )
    paths_eliminated = total_pre_paths - total_post_paths

    return {
        "status": "success",
        "revocations": revocations_classified,
        "metrics": {
            "blast_score_before": round(total_pre_blast, 1),
            "blast_score_after": round(total_post_blast, 1),
            "blast_reduction_percentage": blast_reduction_pct,
            "paths_to_crown_jewels_before": total_pre_paths,
            "paths_to_crown_jewels_after": total_post_paths,
            "paths_eliminated": paths_eliminated,
            "total_business_actions_blocked": sum(r["blocked_events_count"] for r in revocations_classified),
        },
    }
