from __future__ import annotations

import random
from collections import Counter
from typing import Any


CLUSTER_DESCRIPTIONS = {
    0: "Normal business hours actor",
    1: "High-frequency night actor",
    2: "Bulk exporter",
    3: "Admin operation heavy",
    4: "Mixed anomalous pattern",
}


def cluster_events(events: list[dict[str, Any]]) -> dict[str, int]:
    """Assigns each event to a stubbed cluster label keyed by timestamp and user_id."""
    return {f"{event.get('timestamp', '')}|{event.get('user_id', '')}": random.randint(0, 4) for event in events}


def assign_cluster_to_users(profiles: list[dict[str, Any]], event_clusters: dict[str, int]) -> list[dict[str, Any]]:
    """Assigns each user the most common cluster among their flagged events."""
    for profile in profiles:
        user_clusters: list[int] = []
        for event in profile.get("flagged_events", []):
            key = f"{event.get('timestamp', '')}|{event.get('user_id', '')}"
            if key in event_clusters:
                user_clusters.append(int(event_clusters[key]))
        cluster_label = Counter(user_clusters).most_common(1)[0][0] if user_clusters else 0
        profile["cluster_label"] = cluster_label
        profile["cluster_description"] = CLUSTER_DESCRIPTIONS.get(cluster_label, "Normal business hours actor")
    return profiles
