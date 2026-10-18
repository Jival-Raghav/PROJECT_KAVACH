"""backend/detect/peers.py
Peer Group Segmentation and Anomaly Z-Score Engine for Kavach v2.

Determines peer cohorts via:
1. Hierarchical HR metadata: department -> job_title (or custom peer_group extra).
2. Fallback: Agglomerative / KMeans clustering on entitlement Jaccard vectors or action distributions.
3. Peer group statistics: median entitlements, risk baseline mean/std.
4. Peer Z-score evaluation (flags org outliers with z > 2.0).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np
from core.models import CanonicalBundle, CanonicalIdentity
from sklearn.cluster import AgglomerativeClustering, KMeans


class PeerGroupProfile:

    def __init__(self, group_id: str, member_user_ids: list[str]):
        self.group_id = group_id
        self.member_user_ids = member_user_ids
        self.entitlement_median: float = 0.0
        self.mean_score: float = 0.0
        self.std_score: float = 0.0


def build_peer_groups(
    bundle: CanonicalBundle,
    min_cohort_size: int = 3,
) -> dict[str, str]:
    """Assign every user in the CanonicalBundle to a peer group ID.

    Returns:
    - dict mapping user_id -> peer_group_id
    """
    identities = bundle.identities
    accounts = bundle.accounts
    events = bundle.events
    entitlements = bundle.entitlements

    user_peer_map: dict[str, str] = {}
    ident_lookup: dict[str, CanonicalIdentity] = {i.identity_id: i for i in identities}

    all_users = set(ident_lookup.keys()) | {a.username for a in accounts} | {e.user_key for e in events}

    # ── 1. Check for HR Department & Job Title Hierarchy ──────────────────────
    has_hr_departments = any(i.department for i in identities)

    if has_hr_departments:
        # Step A: compute cohort counts for dept::title vs dept
        dept_title_counts: dict[str, int] = defaultdict(int)
        dept_counts: dict[str, int] = defaultdict(int)

        for i in identities:
            dept = (i.department or "").strip().lower()
            title = (i.job_title or "").strip().lower()
            if dept and title:
                dept_title_counts[f"{dept}::{title}"] += 1
            if dept:
                dept_counts[dept] += 1

        for uid in all_users:
            ident = ident_lookup.get(uid)
            # Custom override from Unified Schema
            if ident and ident.extra.get("peer_group"):
                user_peer_map[uid] = str(ident.extra["peer_group"])
                continue

            if ident and ident.department:
                dept = ident.department.strip().lower()
                title = (ident.job_title or "").strip().lower()

                if title and dept_title_counts.get(f"{dept}::{title}", 0) >= min_cohort_size:
                    user_peer_map[uid] = f"{dept}::{title}"
                elif dept:
                    user_peer_map[uid] = dept
                else:
                    user_peer_map[uid] = "general"
            else:
                user_peer_map[uid] = "unassigned_peer"

        return user_peer_map

    # ── 2. Fallback: Clustering Entitlements or Event Actions ──────────────────
    user_list = sorted(all_users)
    if len(user_list) <= 3:
        for u in user_list:
            user_peer_map[u] = "peer_cluster_0"
        return user_peer_map

    # If entitlements exist: build Jaccard binary vectors
    if len(entitlements) > 0:
        all_ents = sorted({e.entitlement for e in entitlements})
        ent_idx = {e: idx for idx, e in enumerate(all_ents)}
        user_ent_vectors = np.zeros((len(user_list), len(all_ents)), dtype=float)

        user_to_pos = {u: idx for idx, u in enumerate(user_list)}
        for e in entitlements:
            # find corresponding user
            for u in (e.account_id,):
                if u in user_to_pos:
                    user_ent_vectors[user_to_pos[u], ent_idx[e.entitlement]] = 1.0

        n_clusters = max(2, min(5, len(user_list) // 3))
        try:
            clustering = AgglomerativeClustering(n_clusters=n_clusters, metric="cosine", linkage="average")
            labels = clustering.fit_predict(user_ent_vectors)
        except Exception:
            # fallback if all zeros or singular
            labels = [i % n_clusters for i in range(len(user_list))]

        for u, lbl in zip(user_list, labels):
            user_peer_map[u] = f"entitlement_cluster_{lbl}"

        return user_peer_map

    # Fallback to action frequency clustering from events
    if len(events) > 0:
        all_actions = sorted({e.action for e in events})
        act_idx = {a: idx for idx, a in enumerate(all_actions)}
        user_act_vectors = np.zeros((len(user_list), len(all_actions)), dtype=float)
        user_to_pos = {u: idx for idx, u in enumerate(user_list)}

        for ev in events:
            if ev.user_key in user_to_pos:
                user_act_vectors[user_to_pos[ev.user_key], act_idx[ev.action]] += 1.0

        # Row-normalize
        row_sums = user_act_vectors.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        norm_vectors = user_act_vectors / row_sums

        n_clusters = max(2, min(5, len(user_list) // 3))
        try:
            km = KMeans(n_clusters=n_clusters, random_state=42, n_init=5)
            labels = km.fit_predict(norm_vectors)
        except Exception:
            labels = [i % n_clusters for i in range(len(user_list))]

        for u, lbl in zip(user_list, labels):
            user_peer_map[u] = f"behavior_cluster_{lbl}"

        return user_peer_map

    # Final fallback
    for u in user_list:
        user_peer_map[u] = "general_peer"
    return user_peer_map


def compute_peer_medians(
    bundle: CanonicalBundle,
    user_peer_map: dict[str, str],
) -> dict[str, float]:
    """Compute peer median entitlement counts for each user."""
    entitlements = bundle.entitlements
    user_counts: dict[str, int] = defaultdict(int)
    for e in entitlements:
        user_counts[e.account_id] += 1

    group_counts: dict[str, list[int]] = defaultdict(list)
    for uid, gid in user_peer_map.items():
        group_counts[gid].append(user_counts.get(uid, 0))

    group_medians: dict[str, float] = {}
    for gid, counts in group_counts.items():
        group_medians[gid] = float(np.median(counts)) if counts else 0.0

    return {uid: group_medians.get(user_peer_map.get(uid, ""), 0.0) for uid in user_peer_map}


def evaluate_peer_zscores(
    user_scores: dict[str, float],
    user_peer_map: dict[str, str],
    z_threshold: float = 2.0,
) -> dict[str, dict[str, Any]]:
    """Compute per-user z-score relative to their peer group baseline.

    Returns dict mapping user_id -> {
        "peer_group": str,
        "peer_mean": float,
        "peer_std": float,
        "z_score": float,
        "is_peer_outlier": bool,
    }
    """
    # Group scores
    group_scores: dict[str, list[float]] = defaultdict(list)
    for uid, score in user_scores.items():
        gid = user_peer_map.get(uid, "general")
        group_scores[gid].append(score)

    group_stats: dict[str, tuple[float, float]] = {}
    for gid, scores in group_scores.items():
        mean_val = float(np.mean(scores)) if scores else 0.0
        std_val = float(np.std(scores)) if len(scores) > 1 else 0.0
        group_stats[gid] = (mean_val, std_val)

    outliers: dict[str, dict[str, Any]] = {}
    for uid, score in user_scores.items():
        gid = user_peer_map.get(uid, "general")
        mean_val, std_val = group_stats.get(gid, (0.0, 0.0))
        z = (score - mean_val) / (std_val + 1e-4) if std_val > 0.01 else 0.0
        is_outlier = bool(z > z_threshold)

        outliers[uid] = {
            "peer_group": gid,
            "peer_mean": round(mean_val, 2),
            "peer_std": round(std_val, 2),
            "z_score": round(float(z), 2),
            "is_peer_outlier": is_outlier,
        }

    return outliers
