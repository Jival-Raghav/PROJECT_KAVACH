"""backend/api/detect.py
FastAPI router for Phase 3: Detection Core Generalization.

Endpoints:
- POST /api/detect/run: Trigger generalized detection on a canonical bundle.
- GET /api/detect/{run_id}/results: Retrieve full user profiles, risk scores, peer context, and metrics.
- GET /api/detect/features: Feature degradation matrix showing active and auto-skipped features.
- GET /api/detect/sod-rules: Active Separation-of-Duties (SoD) policies.
"""
from __future__ import annotations

from typing import Any

from detect.features import extract_canonical_features
from detect.heuristics import load_sod_rules
from detect.models import DetectionResult, run_detection
from detect.peers import build_peer_groups, compute_peer_medians
from fastapi import APIRouter, HTTPException, Query
from ingest.legacy_adapter import load_legacy_bundle
from pydantic import BaseModel

router = APIRouter(prefix="/api/detect", tags=["Detection Core"])

# In-memory cache of recent detection results per run_id
_DETECTION_CACHE: dict[str, DetectionResult] = {}


class RunDetectionPayload(BaseModel):
    run_id: str = "default"
    contamination: float | None = None
    self_calibrate: bool | None = None
    custom_feature_defs: list[dict[str, Any]] | None = None


@router.post("/run")
def trigger_detection(payload: RunDetectionPayload) -> dict[str, Any]:
    """Trigger generalized detection on a canonical bundle."""
    try:
        bundle = load_legacy_bundle(run_id=payload.run_id)
        result = run_detection(
            bundle=bundle,
            contamination=payload.contamination,
            self_calibrate=payload.self_calibrate,
            custom_feature_defs=payload.custom_feature_defs,
        )
        _DETECTION_CACHE[result.run_id] = result

        return {
            "status": "success",
            "run_id": result.run_id,
            "user_count": len(result.user_profiles),
            "contamination": result.contamination,
            "metrics": result.metrics,
            "active_features": result.feature_result.active_features,
            "skipped_features": result.feature_result.skipped_features,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection run failed: {e}") from e


@router.get("/features")
def get_feature_matrix_status(run_id: str = Query("default")) -> dict[str, Any]:
    """Inspect feature degradation matrix and availability status for a dataset."""
    try:
        bundle = load_legacy_bundle(run_id=run_id)
        peer_map = build_peer_groups(bundle)
        peer_medians = compute_peer_medians(bundle, peer_map)
        feat_res = extract_canonical_features(bundle=bundle, peer_medians=peer_medians)

        return {
            "status": "success",
            "run_id": run_id,
            "active_features": feat_res.active_features,
            "skipped_features": feat_res.skipped_features,
            "total_users": len(feat_res.user_ids),
            "matrix_dimensions": list(feat_res.matrix.shape),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect features: {e}") from e


@router.get("/sod-rules")
def get_sod_rules() -> dict[str, Any]:
    """Return configured Separation-of-Duties (SoD) policies."""
    try:
        rules = load_sod_rules()
        return {
            "status": "success",
            "rules_count": len(rules),
            "rules": [vars(r) for r in rules],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load SoD rules: {e}") from e


@router.get("/{run_id}/results")
def get_detection_results(run_id: str) -> dict[str, Any]:
    """Retrieve full detection results, user risk profiles, and metrics for a run."""
    result = _DETECTION_CACHE.get(run_id)
    if not result:
        # Attempt to run on-demand if run_id is default or legacy
        try:
            bundle = load_legacy_bundle(run_id=run_id)
            result = run_detection(bundle=bundle)
            _DETECTION_CACHE[run_id] = result
        except Exception:
            raise HTTPException(
                status_code=404,
                detail=f"Detection results for run_id '{run_id}' not found. Run detection first via POST /api/detect/run",
            )

    return {
        "status": "success",
        "run_id": result.run_id,
        "user_count": len(result.user_profiles),
        "contamination": result.contamination,
        "metrics": result.metrics,
        "active_features": result.feature_result.active_features,
        "skipped_features": result.feature_result.skipped_features,
        "peer_outliers": result.peer_outliers,
        "user_profiles": result.user_profiles,
    }
