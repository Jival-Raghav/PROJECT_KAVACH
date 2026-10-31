from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

import data_loader
import schemas
from models import compliance, isolation_forest, kmeans_events, org_anomaly, sod_violations


pipeline_state: dict[str, Any] = {
    "status": "idle",  # "idle" | "running" | "complete" | "error".
    "progress": 0,  # 0 to 100.
    "message": "",  # Human-readable current step.
    "last_run": None,  # ISO timestamp of the last completed run.
}


def run_pipeline() -> None:
    """Runs the full stubbed pipeline in the required order."""
    try:
        pipeline_state.update({"status": "running", "progress": 0, "message": "Loading data"})
        raw_users = data_loader.load_users()
        raw_events = data_loader.load_events()
        profiles = [schemas.make_stub_profile(user_row) for user_row in raw_users]

        pipeline_state.update({"progress": 20, "message": "Scoring users"})
        isolation_forest.score_users(profiles, raw_events)

        pipeline_state.update({"progress": 40, "message": "Clustering events"})
        event_clusters = kmeans_events.cluster_events(raw_events)
        kmeans_events.assign_cluster_to_users(profiles, event_clusters)

        pipeline_state.update({"progress": 60, "message": "Detecting org anomalies"})
        org_anomaly.detect_org_anomalies(profiles)

        pipeline_state.update({"progress": 75, "message": "Checking SoD violations"})
        for profile in profiles:
            user_events = data_loader.get_events_for_user(str(profile.get("user_id", "")), raw_events)
            sod_violations.check_sod_violations(profile, user_events)

        pipeline_state.update({"progress": 88, "message": "Computing compliance gaps"})
        for profile in profiles:
            compliance.compute_compliance_gaps(profile)

        pipeline_state.update({"progress": 95, "message": "Saving results"})
        data_loader.save_profiles(profiles)

        pipeline_state.update(
            {
                "status": "complete",
                "progress": 100,
                "message": "Pipeline complete",
                "last_run": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as exc:  # pragma: no cover - pipeline failure path.
        pipeline_state.update({"status": "error", "message": str(exc)})
        raise


def run_pipeline_async() -> None:
    """Starts the pipeline in a background thread and marks the state as running immediately."""
    pipeline_state.update({"status": "running", "progress": 0, "message": "Loading data"})
    threading.Thread(target=run_pipeline, daemon=True).start()
