"""backend/detect/scoring.py
Self-Calibrating Score Fusion and Ground-Truth Evaluation Engine for Kavach v2.

Features:
- Score-distribution knee estimation for dynamic Isolation Forest contamination.
- 0–100 score normalization per organization.
- Weighted fusion of ML anomaly score (60%) and heuristic rule violations (40%).
- Ground-truth evaluation (Precision, Recall, F1, PR-AUC).
"""
from __future__ import annotations

from typing import Any

import numpy as np
from config import get_settings
from sklearn.metrics import average_precision_score, precision_recall_fscore_support


def estimate_knee_contamination(
    raw_decision_scores: np.ndarray,
    min_contamination: float = 0.05,
    max_contamination: float = 0.40,
) -> float:
    """Estimate optimal contamination rate from the distribution knee of anomaly scores.

    Raw scores: negative values indicate outliers.
    """
    if len(raw_decision_scores) < 10:
        return 0.15

    sorted_scores = np.sort(raw_decision_scores)
    n = len(sorted_scores)

    # Difference / curvature along the sorted score curve
    diffs = np.diff(sorted_scores)
    second_diffs = np.diff(diffs)

    if len(second_diffs) > 0:
        knee_idx = int(np.argmax(second_diffs)) + 1
        est = (knee_idx + 1) / float(n)
        return float(np.clip(est, min_contamination, max_contamination))

    return 0.20


def normalize_to_100(scores: np.ndarray) -> np.ndarray:
    """Normalize raw values to 0–100 scale where 100 is most anomalous."""
    if len(scores) == 0:
        return np.array([])
    s_min = np.min(scores)
    s_max = np.max(scores)
    if abs(s_max - s_min) < 1e-6:
        return np.zeros_like(scores)

    # Invert so lowest raw score (most anomalous) becomes 100
    norm = (s_max - scores) / (s_max - s_min) * 100.0
    return np.clip(norm, 0.0, 100.0)


def fuse_scores(
    user_ids: list[str],
    ml_scores_100: np.ndarray,
    user_findings: dict[str, list[dict[str, Any]]],
    weight_ml: float | None = None,
    weight_heuristics: float | None = None,
) -> list[dict[str, Any]]:
    """Combine ML anomaly score and heuristic rule findings into a unified risk profile."""
    cfg = get_settings()
    w_ml = weight_ml if weight_ml is not None else getattr(cfg, "WEIGHT_ML", 0.60)
    w_heur = weight_heuristics if weight_heuristics is not None else getattr(cfg, "WEIGHT_HEURISTICS", 0.40)

    results: list[dict[str, Any]] = []

    for idx, uid in enumerate(user_ids):
        ml_score = float(ml_scores_100[idx]) if idx < len(ml_scores_100) else 0.0
        findings = user_findings.get(uid, [])

        # Heuristic score is sum of finding weights capped at 100
        raw_heur_score = sum(float(f.get("score_weight", 10.0)) for f in findings)
        heur_score = min(100.0, raw_heur_score)

        # Fused risk score
        fused = w_ml * ml_score + w_heur * heur_score

        # Check for hard rules
        has_critical = any(f.get("severity") == "critical" for f in findings)
        has_hard_rule = any(f.get("hard_rule") for f in findings)

        if has_critical:
            fused = max(fused, 85.0)
        elif has_hard_rule:
            fused = max(fused, 65.0)

        fused = round(min(100.0, max(0.0, fused)), 1)

        # Assign severity tier
        if fused >= 80.0:
            severity = "CRITICAL"
        elif fused >= 60.0:
            severity = "HIGH"
        elif fused >= 40.0:
            severity = "REVIEW"
        else:
            severity = "INFORMATIONAL"

        results.append({
            "user_id": uid,
            "risk_score": fused,
            "ml_score": round(ml_score, 1),
            "heuristic_score": round(heur_score, 1),
            "severity": severity,
            "findings": findings,
            "flags": [f.get("name", "Flag") for f in findings],
        })

    # Sort descending by risk score
    results.sort(key=lambda r: float(r["risk_score"]), reverse=True)
    return results


def evaluate_detection_metrics(
    y_true: np.ndarray,
    risk_scores: np.ndarray,
    threshold: float = 50.0,
) -> dict[str, Any]:
    """Compute ground-truth evaluation metrics: Precision, Recall, F1, PR-AUC."""
    if len(y_true) == 0 or np.all(y_true == 0):
        return {
            "status": "unlabelled",
            "precision": None,
            "recall": None,
            "f1": None,
            "pr_auc": None,
        }

    y_pred = (risk_scores >= threshold).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )

    try:
        pr_auc = float(average_precision_score(y_true, risk_scores / 100.0))
    except Exception:
        pr_auc = 0.0

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    total = len(y_true)
    acc = round((tp + tn) / total, 4) if total > 0 else 0.0

    return {
        "status": "evaluated",
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "accuracy": acc,
        "pr_auc": round(pr_auc, 4),
        "threshold": threshold,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }
