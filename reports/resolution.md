# Identity Resolution Benchmark Report (Phase 2)

**Timestamp:** 2026-10-17 07:26:26 UTC  
**Run ID:** `bench_resolution_v2`  
**Overall Status:** PASS

---

## 1. Executive Summary

Feature 1b (Identity Resolution Engine) unifies fragmented user accounts across directories, IdPs, and infrastructure into canonical **Golden Identities**, while detecting high-risk credential sprawl (**orphans**, **leaver-active**, **dormant**, **service**, and **shared** accounts).

| Metric | Target | Benchmark Result | Status |
|---|---|---|---|
| **Pair Precision** | $\ge 95.0\%$ | **100.00%** | PASS |
| **Pair Recall** | $\ge 90.0\%$ | **100.00%** | PASS |
| **Conflicting Employee ID Merges** | **0** | **0** | PASS |
| **Leaver-Active Detection Recall** | $\ge 95.0\%$ | **100.00%** | PASS |
| **Orphan Account Detection Recall** | $\ge 95.0\%$ | **100.00%** | PASS |

---

## 2. Hard Invariant Verification: Constrained Union-Find

A core requirement of ISPAD v2 is that records carrying differing non-null employee IDs are **never merged**, regardless of fuzzy name similarity, nickname equivalence, or matching surname.

- **Planted Conflicting ID Pairs Tested:** `2`
- **Merges Allowed:** `0`
- **Refused Merges Recorded in Engine:** `0`

---

## 3. Account Sprawl & Security Classifications

| Classification | Count Detected | Risk Level | Description |
|---|---|---|---|
| **Leaver-Active** | `10` | Critical | Terminated HR employees retaining active directory logins or post-departure events |
| **Orphaned** | `18` | High | Active system accounts with no corresponding HR identity |
| **Shared** | `0` | High | Generic or concurrent multi-IP/geographic sprawling access |
| **Dormant** | `0` | Medium | Active accounts with no login activity exceeding threshold (90 days) |
| **Service** | `5` | Medium / Low | Daemons, automated pipelines, and batch service credentials |
| **Standard Human** | `34` | Low | Verified active employee accounts |

---

## 4. Pipeline Diagnostics

- **Total Canonical Accounts Analyzed:** `67`
- **Total Canonical HR Identities:** `27`
- **Golden Identity Clusters Formed:** `50`
- **Account Links Generated:** `67`
- **Candidate Pairs Scored (Post-Blocking):** `302`
- **Review Queue Items (0.70 - 0.90 Band):** `5`
