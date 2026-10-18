# Kavach v2: Consolidated Benchmark Results

**Run date:** 2026-10-18. All figures below were produced by the scripts and live runs named in each section. The per-benchmark detail reports sit alongside this file in `reports/`.

---

## 1. Summary

| Area | Result | Evidence |
| :--- | :--- | :--- |
| Attacks dismissed (ablation, 4 attacks) | **0** | `da_ablation.md` |
| Attacks confirmed (live demo, 7 attacks) | **7 of 7**, with the LLM on and with it off | section 3 |
| Devil's Advocate false-positive reduction | **80%** (5 to 1, out of 9 alerts) | `da_ablation.md` |
| Alert quality after adjudication | Precision 0.444 to **0.800**, F1 0.615 to **0.889** | `da_ablation.md` |
| Detection F1 vs legacy baseline | 0.518 to **0.789** | `detection.md` |
| Identity resolution | Pair precision and recall **100%**, 0 conflicting-ID merges | `resolution.md` |
| Schema Autopilot | **100%** on 7 schemas, 0 crashes on malformed input | `mapping.md` |
| Prompt-injection payloads neutralised (static check) | **32 of 32**; 12 of 32 actively detected | `redteam.md` |
| Automated tests | 94 of 96 on the demo dataset (see section 6) | `pytest tests/` |

---

## 2. Devil's Advocate ablation

Scope: 9 planted cases (5 benign look-alikes, 4 malicious). Script: `scripts/bench_da_ablation.py`.

| Configuration | Alerts | False positives | FP reduction | Attacks missed | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| A: ML only | 9 | 5 | 0% | 0 | 0.444 | 1.000 | 0.615 |
| B: ML + Prosecutor | 9 | 5 | 0% | 0 | 0.444 | 1.000 | 0.615 |
| C: Devil's Advocate without tools | 9 | 5 | 0% | 0 | 0.444 | 1.000 | 0.615 |
| **D: Devil's Advocate with tools** | **5** | **1** | **80%** | **0** | **0.800** | **1.000** | **0.889** |

Only evidence-grounded defence (D) reduces false positives; a prosecutor alone (B) or a tool-less defence (C) does not.

---

## 3. Live end-to-end run on the demo dataset

Dataset: `data/demo_flood`. It has 407 identities and 4,244 events, with 7 planted attacks and 6 look-alike benign cases. Each case went through the full pipeline (Prosecutor, Devil's Advocate with tools, Adjudicator).

### 3a. Verdicts against ground truth

| Ground truth | CONFIRMED_THREAT | NEEDS_REVIEW | MITIGATED_BENIGN |
| :--- | :---: | :---: | :---: |
| Attack (7) | **7** | 0 | 0 |
| Benign look-alike (6) | 2 | 3 | 1 |

The two confirmed benign cases are `USR9104` (a recent role transfer; a genuine false positive) and `USR9106` (a dormant break-glass admin, flagged by design under a hard rule, with the CISO exception cited and recommended action NO_ACTION).

### 3b. Alerts that would page an analyst (CONFIRMED_THREAT only)

| Metric | Naive rule (high-sensitivity data AND off-hours) | Kavach |
| :--- | :---: | :---: |
| Alerts | 13 | 9 |
| False positives | 6 | 2 |
| Precision | 0.54 | 0.78 |
| Recall | 1.00 | 1.00 |
| F1 | 0.70 | 0.88 |

The naive rule is a baseline defined for this report, not a vendor product.

### 3c. LLM on vs LLM off (deterministic mode)

| | LLM on | LLM off |
| :--- | :---: | :---: |
| Attacks confirmed | 7 of 7 | 7 of 7 |
| Benign cleared | 1 | 0 |
| Benign at needs-review | 3 | 4 |
| Benign confirmed as threat | 2 | 2 |

The no-attack-dismissed guarantee holds without the LLM because hard rules, the citation check and the severity floor are enforced in code. Deterministic mode ran 27 cases in 15.6 seconds.

### 3d. Triage funnel

| Stage | Count |
| :--- | :---: |
| Identities | 407 |
| Flagged by risk score (>= 40) | 27 |
| HIGH or CRITICAL severity | 13 (3 critical, 10 high) |
| Top 10 by risk score | all 7 attackers + 3 benign look-alikes |

**Known limitation:** 14 night-shift support users with no roster data cannot be cleared because the Devil's Advocate has no evidence to cite. All 14 remain flagged, 13 of them at the lowest (REVIEW) severity.

### 3e. Prompt-injection case (`USR9206`)
A log field instructing the model to return `MITIGATED_BENIGN` was run through the full pipeline with a live LLM. The verdict stayed `CONFIRMED_THREAT / HIGH` (n=1).

---

## 4. Detection core (`detection.md`)

- Dataset A: 300 users, 108 anomalous. F1 **0.789** (legacy 0.518), precision 0.782, recall 0.796, PR-AUC 0.741.
- The best threshold was chosen on the same data. F1 stays between 0.78 and 0.79 across thresholds 30 to 60.
- Datasets B, C and D (2 to 5 entities each) demonstrate graceful degradation: 10, 12 and 10 active features, no crashes.

## 5. Identity resolution and schema mapping

- Resolution (`resolution.md`): 67 accounts into 50 golden identities; leaver-active (10) and orphaned (18) accounts found at 100% recall.
- Mapping (`mapping.md`): 100% accuracy on 7 schemas (43 fields); 0 crashes on empty, one-column and binary files.

---

## 6. Red-team and engineering quality

### Red-team (`redteam.md`)
32 payloads across 8 categories: 32 of 32 neutralised, 12 of 32 (37.5%) actively detected, 0 of 100 benign samples redacted. This is a static prompt-construction check; the report states its method and limits.

### Tests
`pytest tests/`: 94 passed, 2 failed in 2.8 seconds. Both failures are in `tests/test_legacy_seam.py` and occur because the demo dataset is applied (the test expects 300 identities; the live data has 407). Restore the original data with `python scripts/gen_demo_flood.py --restore` and re-run for the full-suite result.

---

## 7. Reproduce

```
pytest tests/
python scripts/bench_da_ablation.py
python scripts/bench_redteam.py
python scripts/bench_detection.py
python scripts/bench_resolution.py
python scripts/bench_mapping.py
```
The live run in section 3 uses `POST /api/investigate/<user_id>` with `{"use_llm": true|false}` against the demo dataset.
