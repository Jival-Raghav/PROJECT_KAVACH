"""backend/detect/__init__.py
Phase 3: Detection Core Generalization package for Kavach v2.
"""
from detect.features import extract_canonical_features
from detect.heuristics import evaluate_heuristics, load_sod_rules
from detect.models import cluster_behavioral_events, run_detection, train_isolation_forest
from detect.peers import build_peer_groups, evaluate_peer_zscores
from detect.scoring import evaluate_detection_metrics, fuse_scores, normalize_to_100

__all__ = [
    "extract_canonical_features",
    "load_sod_rules",
    "evaluate_heuristics",
    "train_isolation_forest",
    "cluster_behavioral_events",
    "run_detection",
    "build_peer_groups",
    "evaluate_peer_zscores",
    "fuse_scores",
    "normalize_to_100",
    "evaluate_detection_metrics",
]
