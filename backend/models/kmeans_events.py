"""
models/kmeans_events.py
Real KMeans clustering on event behavioral features.
Replaces the random.randint stub.

Each event is represented by 6 numeric features.
Users are assigned the modal cluster of their flagged events.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from config import get_settings

CLUSTER_DESCRIPTIONS: dict[int, str] = {
    0: "Normal business hours actor",
    1: "High-frequency night actor",
    2: "Bulk exporter",
    3: "Admin operation heavy",
    4: "Mixed anomalous pattern",
}

_EVENT_FEATURE_KEYS = [
    "hour_of_day",
    "is_after_hours",
    "is_high_sensitivity",
    "is_failure",
    "is_admin_op",
    "is_export",
]


def cluster_events(events: list[dict[str, Any]]) -> dict[str, int]:
    """
    Fits KMeans on the event feature matrix.
    Returns a dict keyed by 'timestamp|user_id' → cluster_label (int 0–4).
    """
    if not events:
        return {}

    cfg = get_settings()
    k = cfg.KMEANS_K

    from preprocessing.feature_engineering import _build_event_features

    feat_dicts = _build_event_features(events)

    matrix = np.array(
        [[fd[key] for key in _EVENT_FEATURE_KEYS] for fd in feat_dicts],
        dtype=np.float64,
    )

    # Standardise so hour_of_day (0–23) doesn't dominate the binary features
    scaler = StandardScaler()
    matrix_scaled = scaler.fit_transform(matrix)

    # Guard: KMeans needs at least k samples
    actual_k = min(k, len(events))
    km = KMeans(n_clusters=actual_k, random_state=42, n_init=10)
    labels: np.ndarray = km.fit_predict(matrix_scaled)

    # Map cluster centroids to human labels by characteristic features
    label_map = _map_clusters_to_descriptions(km.cluster_centers_, actual_k)

    result: dict[str, int] = {}
    for i, fd in enumerate(feat_dicts):
        raw_label = int(labels[i])
        mapped = label_map.get(raw_label, raw_label)
        result[fd["_key"]] = mapped

    return result


def _map_clusters_to_descriptions(
    centers: np.ndarray, k: int
) -> dict[int, int]:
    """
    Heuristically map raw KMeans cluster indices to our 5 fixed descriptions
    by inspecting centroid characteristics.

    centers shape: (k, 6) — [hour, is_after_hours, is_high_sens, is_fail, is_admin, is_export]
    """
    # Indices in the scaled feature space that correspond to each original feature
    # (we do a best-effort heuristic since scaling shifts values)
    mapping: dict[int, int] = {}
    used_descriptions: set[int] = set()

    for cluster_idx in range(k):
        c = centers[cluster_idx]
        # c[0]=hour, c[1]=after_hours, c[2]=high_sens, c[3]=failure, c[4]=admin, c[5]=export

        if c[5] > 0.5:          # high export centroid
            desc = 2
        elif c[4] > 0.5:        # high admin_op centroid
            desc = 3
        elif c[1] > 0.3:        # high after_hours centroid
            desc = 1
        elif any(abs(c[i]) > 0.3 for i in [2, 3]):
            desc = 4            # mixed anomalous
        else:
            desc = 0            # normal

        # Avoid duplicate description assignment
        while desc in used_descriptions and desc < 4:
            desc += 1
        used_descriptions.add(desc)
        mapping[cluster_idx] = desc

    return mapping


def assign_cluster_to_users(
    profiles: list[dict[str, Any]], event_clusters: dict[str, int]
) -> list[dict[str, Any]]:
    """Assigns each user the most common cluster among their flagged events."""
    for profile in profiles:
        user_clusters: list[int] = []
        for event in profile.get("flagged_events", []):
            key = f"{event.get('timestamp', '')}|{event.get('user_id', '')}"
            if key in event_clusters:
                user_clusters.append(event_clusters[key])

        cluster_label = (
            Counter(user_clusters).most_common(1)[0][0] if user_clusters else 0
        )
        profile["cluster_label"] = cluster_label
        profile["cluster_description"] = CLUSTER_DESCRIPTIONS.get(
            cluster_label, "Normal business hours actor"
        )

    return profiles
