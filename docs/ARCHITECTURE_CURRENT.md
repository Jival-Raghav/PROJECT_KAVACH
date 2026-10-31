# Current Architecture & Seam Audit (Phase 0)

## 1. Overview
This document audits the legacy state of the ISPAD repository prior to the v2 refactor, identifying the existing data flow, where hard-coded column names exist, where ML models are trained, and how LLMs are invoked.

## 2. Legacy Data Flow
1. **Raw Ingestion**:
   - `backend/data_loader.py` reads `backend/data/identity_users.csv` and `identity_events.csv` using pandas into raw dict rows.
   - Initial user profiles are generated with `schemas.make_stub_profile()`.
2. **Scoring & Flagging**:
   - `backend/models/isolation_forest.py` extracts a 18-element feature vector (`preprocessing/feature_engineering.py`) and trains an `IsolationForest(n_estimators=200)` model.
   - Scores are inverted, scaled to 0–100 via `MinMaxScaler`, and combined with a 40% rule score.
3. **Clustering & Org Baselines**:
   - `backend/models/kmeans_events.py` clusters raw events using KMeans ($k=5$).
   - `backend/models/org_anomaly.py` computes department risk mean and standard deviation, flagging users $> 2\sigma$ above their department baseline.
4. **Heuristics & Simulation**:
   - `backend/models/sod_violations.py` checks 4 hard-coded SoD rules.
   - `backend/models/compliance.py` checks 3 compliance rules (NIST AC-2, AC-6, GDPR Art. 32).
   - `backend/models/breach_simulator.py` builds an ad-hoc 2-hop graph across user access lists.
5. **Persistence**:
   - Global serialized snapshot stored at `backend/data/user_profiles.json` and analyst feedback at `backend/data/feedback.json`.
6. **Dual-LLM Pass**:
   - `backend/llm/narrator.py` lazily initializes Pass 1 (Prosecutor) and Pass 2 (Devil's Advocate), streaming SSE chunks to the frontend.

## 3. Hard-Coded Column Names & Literals
Prior to v2, specific column names were accessed across multiple files:
- In `backend/preprocessing/feature_engineering.py`:
  - User fields: `systems_access`, `is_active`, `days_inactive`, `privilege_level`, `hire_date`, `department`
  - Event fields: `time_classification`, `resource_sensitivity`, `status`, `action`, `resource`, `timestamp`, `user_id`
- In `backend/models/sod_violations.py`:
  - `privilege_level`, `action`, `resource_sensitivity`, `timestamp`, `resource`
- In `backend/models/compliance.py`:
  - `is_active`, `days_inactive`, `privilege_level`, `event_count`, `fail_ratio`, `high_sensitivity_ratio`, `login_fail_count`, `systems_access`, `job_title`

## 4. Phase 0 Seam Design
To decouple the pipeline from dataset-specific column names:
- **Canonical Model (`backend/core/models.py`)**: All downstream detectors and LLM prompts will consume canonical entities: `CanonicalIdentity`, `CanonicalAccount`, `CanonicalEntitlement`, `CanonicalEvent`, `CanonicalSystem`, and `OrgContext`.
- **Legacy Adapter Seam (`backend/ingest/legacy_adapter.py`)**: `load_canonical(run_id=None)` reads legacy CSVs and maps them into a `CanonicalBundle`.
- **Zero-Literal Enforcement**: A test (`tests/test_column_literals.py`) verifies that legacy raw header strings (`systems_access`, `time_classification`, `days_inactive`, `is_active`) do not appear outside the `ingest/` package and `legacy_adapter.py`.
