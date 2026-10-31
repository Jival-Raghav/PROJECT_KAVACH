# Generalized Detection Core Benchmark Report (Phase 3)

**Generated:** 2026-10-17 09:58:08 UTC  
**Target:** ISPAD v2 Generalized Detection & Scoring Engine

---

## 1. Executive Summary

Phase 3 introduces a schema-independent, multi-source anomaly detection engine engineered entirely on canonical data representations. It delivers:
- **Self-Calibrating Isolation Forest**: Dynamically adjusts contamination based on score distribution knees (calibrated contamination: `0.050`).
- **Hybrid Score Fusion**: 60% ML isolation score + 40% security heuristics & SoD violations.
- **Hierarchical & Behavioral Peer Grouping**: Falls back from `department -> job_title` to Jaccard entitlement clustering and action distribution clustering when organizational metadata is absent.
- **Graceful Feature Degradation**: Evaluated across disparate multi-source schemas (Datasets A, B, C, D) with automatic skipping of missing fields and 0 raw column leaks.

---

## 2. Dataset A Benchmark vs Legacy Baseline

### Performance Comparison
| Metric | Legacy Baseline (Single Dataset) | Phase 3 Generalized Engine | Delta / Improvement |
| :--- | :---: | :---: | :---: |
| **Best F1 Score** | `0.518` (thresh=30) | **`0.7890`** (thresh=40.0) | **++0.2710** |
| **Precision** | `0.710` | **`0.7818`** | **++0.0718** |
| **Recall** | `0.407` | **`0.7963`** | **++0.3893** |
| **Accuracy** | `0.727` | **`0.8467`** | **++0.1197** |
| **True Positives (TP)** | 44 | **86** | +42 |
| **False Positives (FP)** | 18 | **24** | +6 |
| **PR-AUC** | 0.54 | **`0.7406`** | **++0.2006** |

### Threshold Sweep Table
| Threshold | Precision | Recall | F1 Score | Accuracy | TP | FP | FN | TN |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20 | 0.632 | 0.843 | **0.722** | 0.767 | 91 | 53 | 17 | 139 |
| 25 | 0.685 | 0.824 | **0.748** | 0.800 | 89 | 41 | 19 | 151 |
| 30 | 0.746 | 0.815 | **0.779** | 0.833 | 88 | 30 | 20 | 162 |
| 35 | 0.770 | 0.806 | **0.787** | 0.843 | 87 | 26 | 21 | 166 |
| 40 | 0.782 | 0.796 | **0.789** **(Best F1)** | 0.847 | 86 | 24 | 22 | 168 |
| 45 | 0.780 | 0.787 | **0.783** | 0.843 | 85 | 24 | 23 | 168 |
| 50 | 0.787 | 0.787 | **0.787** | 0.847 | 85 | 23 | 23 | 169 |
| 55 | 0.787 | 0.787 | **0.787** | 0.847 | 85 | 23 | 23 | 169 |
| 60 | 0.787 | 0.787 | **0.787** | 0.847 | 85 | 23 | 23 | 169 |

---

## 3. Multi-Schema Graceful Degradation Matrix

| Dataset | Schema Type | Entities | Active Features | Skipped Features | Peer Group Mode |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Dataset A** | Legacy ISPAD (Users + Events) | 300 | 13 | 0 | Hierarchical (Department -> Job Title) |
| **Dataset B** | Workday HR + Okta JSONL | 5 | 10 | 3 (`unused_entitlement_ratio`, `sensitivity_ratio`, etc.) | Hierarchical (Workday Org) |
| **Dataset C** | AWS CloudTrail + IAM | 3 | 12 | 1 (HR attributes) | Fallback: Entitlement Jaccard Clustering |
| **Dataset D** | Stress Minimal Events | 2 | 10 | 3 (Entitlements, Sensitivities) | Fallback: Action Distribution Clustering |

---

## 4. Custom Feature Dynamic Injection

- **Standard Matrix Dimension**: `13` features
- **Custom-Injected Matrix Dimension**: `14` features (`+1` dynamic feature `custom_custom_threat_score`)
- **Status**: PASSED. Users can define custom unified schema features with cardinality caps and immediately alter model training.

---

## 5. Architectural Invariants Verified

- [x] **Zero Raw Column Literals**: Ran `test_column_literals.py` over `backend/detect/` with 0 legacy header references.
- [x] **Degradation Resilience**: All 4 datasets executed without exceptions; missing data reasons cleanly reported.
- [x] **F1 Performance**: Dataset A F1 achieved `0.7890`, exceeding previous baseline (`0.518`).
- [x] **Deterministic Calibration**: Isolation Forest contamination self-calibrated to `0.050` using score distribution knee detection.
