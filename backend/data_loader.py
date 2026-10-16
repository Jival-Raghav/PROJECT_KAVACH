from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_CSV = DATA_DIR / "identity_users.csv"
EVENTS_CSV = DATA_DIR / "identity_events.csv"
PROFILES_JSON = DATA_DIR / "user_profiles.json"
FEEDBACK_JSON = DATA_DIR / "feedback.json"


def _safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "active"}


def _normalize_value(value: Any) -> Any:
    if pd.isna(value):
        return ""
    return value


def load_users() -> list[dict[str, Any]]:
    """Reads identity_users.csv and returns raw user rows as dictionaries."""
    if not USERS_CSV.exists():
        return []

    frame = pd.read_csv(USERS_CSV).fillna("")
    rows: list[dict[str, Any]] = []

    for record in frame.to_dict(orient="records"):
        row = {key: _normalize_value(value) for key, value in record.items()}
        systems_access = row.get("systems_access", "")
        if isinstance(systems_access, str):
            row["systems_access"] = [item.strip() for item in systems_access.split("|") if item.strip()]
        elif isinstance(systems_access, list):
            row["systems_access"] = [str(item).strip() for item in systems_access if str(item).strip()]
        else:
            row["systems_access"] = []
        row["is_active"] = _safe_bool(row.get("is_active"))
        row["days_inactive"] = int(row.get("days_inactive", 0) or 0)
        rows.append(row)

    return rows


def load_events() -> list[dict[str, Any]]:
    """Reads identity_events.csv and returns raw event rows as dictionaries."""
    if not EVENTS_CSV.exists():
        return []

    frame = pd.read_csv(EVENTS_CSV).fillna("")
    return [
        {key: _normalize_value(value) for key, value in record.items()}
        for record in frame.to_dict(orient="records")
    ]


def get_events_for_user(user_id: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filters the event list down to the rows that belong to one user."""
    return [event for event in events if str(event.get("user_id", "")) == str(user_id)]


def save_profiles(profiles: list[dict[str, Any]]) -> None:
    """Writes the profile list to data/user_profiles.json using pretty JSON."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROFILES_JSON.write_text(json.dumps(profiles, indent=2, ensure_ascii=True), encoding="utf-8")


def load_profiles() -> list[dict[str, Any]]:
    """Reads data/user_profiles.json and returns the stored profiles list."""
    if not PROFILES_JSON.exists():
        return []
    return json.loads(PROFILES_JSON.read_text(encoding="utf-8"))


def save_feedback(feedback: dict[str, Any]) -> None:
    """Writes the feedback mapping to data/feedback.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    FEEDBACK_JSON.write_text(json.dumps(feedback, indent=2, ensure_ascii=True), encoding="utf-8")


def load_feedback() -> dict[str, Any]:
    """Reads data/feedback.json and returns the feedback mapping."""
    if not FEEDBACK_JSON.exists():
        return {}
    return json.loads(FEEDBACK_JSON.read_text(encoding="utf-8"))
