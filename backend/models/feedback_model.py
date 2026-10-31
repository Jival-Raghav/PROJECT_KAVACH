# ============================================================
# FILE: backend/models/feedback_model.py
# OWNER: Person 1 — ML pipeline
# STATUS: Complete
# DEPENDS ON: data_loader.py, schemas.py
# ============================================================
"""Feedback-based calibration for the Devil's Advocate doubt score.

This module turns analyst feedback into a lightweight calibration layer.
It does not retrain the core detector. Instead, it estimates how likely a
new alert is to be a false positive based on historical suppression patterns
for the same flags, then blends that prior into the LLM-produced doubt score.

Cold start behaviour:
- With no feedback examples, the calibration must not change the model output.
- As feedback accumulates, the historical prior starts to influence the score.
- After enough examples, the feedback layer becomes a meaningful adjustment,
  but it still does not fully override the model signal.
"""
from __future__ import annotations

from typing import Any

import data_loader


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _normalise_flags(profile: dict[str, Any]) -> list[str]:
    flags = profile.get("flags", [])
    if not isinstance(flags, list):
        return []
    return [str(flag).strip() for flag in flags if str(flag).strip()]


def compute_feedback_prior(
    profile: dict[str, Any],
    all_profiles: list[dict[str, Any]],
    feedback: dict[str, Any],
) -> float:
    """Compute a flag-based false-positive prior for one profile.

    For each flag currently present on the user, this scans historical profiles
    that have analyst feedback and measures how often that flag was associated
    with suppression. The per-flag suppression rate is the fraction of matched
    historical examples that were suppressed.

    The final prior is the average of the matched per-flag rates, clamped to the
    [0.0, 1.0] range. If no historical matches exist for the current flags, the
    function returns 0.0 so the feedback layer stays neutral on unseen patterns.
    """
    current_flags = _normalise_flags(profile)
    if not current_flags:
        return 0.0

    profiles_by_user_id: dict[str, dict[str, Any]] = {}
    for historical_profile in all_profiles:
        user_id = str(historical_profile.get("user_id", "")).strip()
        if user_id:
            profiles_by_user_id[user_id] = historical_profile

    feedback_entries = [entry for entry in feedback.values() if isinstance(entry, dict)]
    if not feedback_entries:
        return 0.0

    per_flag_rates: list[float] = []
    for flag in current_flags:
        matched_feedback_count = 0
        suppressed_count = 0

        for user_id, entry in feedback.items():
            if not isinstance(entry, dict):
                continue

            historical_profile = profiles_by_user_id.get(str(user_id).strip())
            if historical_profile is None:
                continue

            historical_flags = set(_normalise_flags(historical_profile))
            if flag not in historical_flags:
                continue

            matched_feedback_count += 1
            if bool(entry.get("suppressed", False)):
                suppressed_count += 1

        if matched_feedback_count:
            per_flag_rates.append(suppressed_count / matched_feedback_count)

    if not per_flag_rates:
        return 0.0

    prior = sum(per_flag_rates) / len(per_flag_rates)
    return _clamp(prior, 0.0, 1.0)


def apply_feedback_calibration(profile: dict[str, Any], model_doubt: float) -> float:
    """Blend model doubt with a feedback-derived prior.

    The schedule is intentionally conservative at low data volume and gradually
    gives the feedback layer more influence as examples accumulate:

        α = max(0.3, 1.0 - (n / 20))

    where n is the total number of feedback examples in feedback.json. With no
    examples, α = 1.0 so the original model_doubt is preserved. Once roughly 20
    examples exist, the feedback prior can contribute substantially, but the
    model never drops below a 30% weight.
    """
    profiles = data_loader.load_profiles()
    feedback = data_loader.load_feedback()

    feedback_prior = compute_feedback_prior(profile, profiles, feedback)
    n = sum(1 for entry in feedback.values() if isinstance(entry, dict))

    # Cold start safety: keep the DA score intact when feedback is scarce.
    # As n grows, feedback gets more weight, but the model always keeps at least 30%.
    alpha = max(0.3, 1.0 - (n / 20.0))

    adjusted_doubt = alpha * float(model_doubt) + (1.0 - alpha) * feedback_prior
    return _clamp(adjusted_doubt, 0.0, 1.0)