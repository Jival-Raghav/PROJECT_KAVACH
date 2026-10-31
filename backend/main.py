from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

import data_loader
from models import breach_simulator
from llm.narrator import generate_narrative, get_provider_status, stream_narrative
from pipeline import pipeline_state, run_pipeline_async, lifespan
from models.kmeans_events import get_cluster_summary


app = FastAPI(title="Identity Sprawl & Privilege Abuse Detection", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FeedbackPayload(BaseModel):
    action: str = Field(..., pattern="^(suppress|unflag)$")
    note: str = ""


def _load_profiles_with_feedback() -> list[dict[str, Any]]:
    profiles = data_loader.load_profiles()
    feedback = data_loader.load_feedback()
    for profile in profiles:
        entry = feedback.get(profile.get("user_id", ""), {})
        if isinstance(entry, dict):
            profile["suppressed"] = bool(entry.get("suppressed", profile.get("suppressed", False)))
            profile["feedback_note"] = str(entry.get("note", profile.get("feedback_note", "")))
    return profiles


def _save_profile_list(updated_profiles: list[dict[str, Any]]) -> None:
    data_loader.save_profiles(updated_profiles)


def _find_profile(profiles: list[dict[str, Any]], user_id: str) -> dict[str, Any] | None:
    for profile in profiles:
        if str(profile.get("user_id", "")) == str(user_id):
            return profile
    return None


def _severity_from_score(risk_score: float) -> str:
    if risk_score >= 80:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 40:
        return "REVIEW"
    return "INFORMATIONAL"


@app.post("/run-pipeline")
def run_pipeline_endpoint() -> dict[str, str]:
    """Triggers the background pipeline run and returns immediately."""
    if pipeline_state.get("status") == "running":
        raise HTTPException(status_code=409, detail="Pipeline already running")
    run_pipeline_async()
    return {"status": "started"}


@app.get("/status")
def get_status() -> dict[str, Any]:
    """Returns the global pipeline state used by the frontend polling loop."""
    return {**pipeline_state, "llm": get_provider_status()}


@app.get("/llm-status")
def get_llm_status() -> dict[str, Any]:
    """Returns LLM provider connectivity status. Use this to check if LM Studio is running."""
    return get_provider_status()


@app.get("/users/risks")
def get_user_risks() -> list[dict[str, Any]]:
    """Loads the latest profiles, applies feedback, and returns them sorted by risk score."""
    profiles = _load_profiles_with_feedback()
    return sorted(profiles, key=lambda profile: float(profile.get("risk_score", 0.0) or 0.0), reverse=True)


@app.get("/users/{user_id}")
def get_user(user_id: str = Path(..., description="The user identifier from the CSV feed.")) -> dict[str, Any]:
    """Returns a single profile by user_id."""
    profile = _find_profile(_load_profiles_with_feedback(), user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")
    return profile


@app.get("/users/{user_id}/narrative")
def get_user_narrative(user_id: str = Path(..., description="The user identifier from the CSV feed.")) -> StreamingResponse:
    """Streams the cached or newly generated narrative back to the frontend as SSE."""
    profiles = _load_profiles_with_feedback()
    profile = _find_profile(profiles, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")

    feedback_context = data_loader.load_feedback().get(str(user_id), {})
    flagged_events = list(profile.get("flagged_events", []))
    all_profiles = profiles

    if profile.get("narrative") is None:
        narrative = generate_narrative(profile, flagged_events, feedback_context, all_profiles=all_profiles)
        profile["narrative"] = narrative
        response = StreamingResponse(
            stream_narrative(profile, flagged_events, feedback_context, all_profiles=all_profiles),
            media_type="text/event-stream",
            background=BackgroundTask(_save_profile_list, profiles),
        )
        return response

    cached_narrative = profile["narrative"]

    def cached_stream():
        full_text = f"PROSECUTION:\n{cached_narrative['prosecution']}\n\nDEVIL'S ADVOCATE:\n{cached_narrative['devils_advocate']}"
        yield f"data: {full_text}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(cached_stream(), media_type="text/event-stream")


@app.post("/feedback/{user_id}")
def post_feedback(user_id: str, payload: FeedbackPayload) -> dict[str, str]:
    """Stores analyst feedback and syncs the suppressed flag back into the profile store."""
    profiles = data_loader.load_profiles()
    profile = _find_profile(profiles, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")

    feedback = data_loader.load_feedback()
    feedback[user_id] = {"suppressed": payload.action == "suppress", "note": payload.note}
    profile["suppressed"] = payload.action == "suppress"
    profile["feedback_note"] = payload.note
    data_loader.save_feedback(feedback)
    data_loader.save_profiles(profiles)
    return {"status": "ok"}


@app.get("/org-anomalies")
def get_org_anomalies() -> list[dict[str, Any]]:
    """Returns a concise view of the profiles whose org anomaly flag is set."""
    profiles = _load_profiles_with_feedback()
    anomalies = []
    for profile in profiles:
        if bool(profile.get("org_anomaly", {}).get("is_anomaly", False)):
            anomalies.append(
                {
                    "user_id": profile.get("user_id", ""),
                    "username": profile.get("username", ""),
                    "department": profile.get("department", ""),
                    "risk_score": profile.get("risk_score", 0.0),
                    "org_anomaly": profile.get("org_anomaly", {}),
                }
            )
    return anomalies


@app.get("/clusters/summary")
def get_clusters_summary() -> list[dict[str, Any]]:
    """Returns per-cluster summary stats for already-scored user profiles."""
    profiles = data_loader.load_profiles()
    if not profiles:
        raise HTTPException(status_code=400, detail="Pipeline has not run yet")
    return get_cluster_summary(profiles)


@app.get("/users/{user_id}/breach-simulation")
def get_user_breach_simulation(user_id: str = Path(..., description="The user identifier from the CSV feed.")) -> dict[str, Any]:
    """Simulates breach impact for a user using direct and two-hop access paths."""
    all_profiles = data_loader.load_profiles()
    if not all_profiles:
        raise HTTPException(status_code=400, detail="Pipeline has not run yet")

    profile = _find_profile(all_profiles, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")

    return breach_simulator.simulate_breach(profile, all_profiles)


@app.get("/stats")
def get_stats() -> dict[str, Any]:
    """Returns dashboard summary values derived from the saved profiles."""
    profiles = _load_profiles_with_feedback()
    total_users = len(profiles)
    critical_count = 0
    high_count = 0
    review_count = 0
    suppressed_count = sum(1 for profile in profiles if bool(profile.get("suppressed", False)))
    risk_scores: list[float] = []
    department_totals: dict[str, list[float]] = {}

    for profile in profiles:
        score = float(profile.get("risk_score", 0.0) or 0.0)
        risk_scores.append(score)
        severity = profile.get("narrative", {}).get("final_severity") if isinstance(profile.get("narrative"), dict) else None
        severity = severity or _severity_from_score(score)
        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1
        elif severity == "REVIEW":
            review_count += 1
        department = str(profile.get("department", "Unknown"))
        department_totals.setdefault(department, []).append(score)

    top_risky_departments = [
        {"dept": department, "avg_score": round(sum(scores) / len(scores), 2)}
        for department, scores in sorted(department_totals.items(), key=lambda item: sum(item[1]) / len(item[1]) if item[1] else 0.0, reverse=True)[:5]
    ]

    return {
        "total_users": total_users,
        "critical_count": critical_count,
        "high_count": high_count,
        "review_count": review_count,
        "suppressed_count": suppressed_count,
        "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0,
        "top_risky_departments": top_risky_departments,
    }
