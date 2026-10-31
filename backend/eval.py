"""
eval.py — Self-evaluation for the Identity Sprawl Detection system.

Since no external label file is provided, this script derives ground truth
from defensible, interpretable rules directly on the raw CSV data.
Each rule is documented so judges can verify the logic.

Usage:
    cd backend
    python eval.py

Outputs:
    - Per-rule anomaly breakdown
    - Precision / Recall / F1 at multiple risk score thresholds
    - Confusion matrix at best threshold
    - Saves results to eval_results.json
"""

from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR     = Path(__file__).parent / "data"
USERS_CSV    = DATA_DIR / "identity_users.csv"
EVENTS_CSV   = DATA_DIR / "identity_events.csv"
PROFILES_JSON = DATA_DIR / "user_profiles.json"
OUTPUT_JSON  = Path(__file__).parent / "eval_results.json"

# ── Ground truth rules ─────────────────────────────────────────────────────────
# Each rule is a dict:
#   name        — short label
#   description — human explanation (for the judge)
#   fn          — takes (user, user_events) → bool
#
# A user is labelled anomalous if ANY rule fires on them.
# Rules are chosen to be unambiguous and directly observable from raw data.

TODAY = date(2026, 4, 1)   # approximate "now" relative to the dataset


def _days_since_hire(user: dict) -> int:
    try:
        hire = datetime.strptime(user["hire_date"], "%Y-%m-%d").date()
        return (TODAY - hire).days
    except Exception:
        return 9999


def _after_hours_ratio(user_events: list[dict]) -> float:
    if not user_events:
        return 0.0
    after = sum(
        1 for e in user_events
        if e["time_classification"] in ("night", "unusual_hours", "weekend")
    )
    return after / len(user_events)


RULES: list[dict] = [
    {
        "name": "STALE_PRIVILEGED_ACCOUNT",
        "description": (
            "Admin or power-user account inactive for more than 30 days. "
            "NIST AC-2 requires periodic review and disabling of stale privileged accounts."
        ),
        "fn": lambda u, evs: (
            u["privilege_level"] in ("admin", "power-user")
            and int(u.get("days_inactive", 0) or 0) > 30
        ),
    },
    {
        "name": "HIGH_SENS_EXPORT_NIGHT",
        "description": (
            "User exported high-sensitivity data during night or unusual hours. "
            "This combination is a strong indicator of data exfiltration risk."
        ),
        "fn": lambda u, evs: any(
            e["action"] == "export_data"
            and e["resource_sensitivity"] == "high"
            and e["time_classification"] in ("night", "unusual_hours")
            for e in evs
        ),
    },
    {
        "name": "SERVICE_ACCOUNT_ADMIN_OP",
        "description": (
            "Service account performing admin_operation events. "
            "Service accounts should have narrow, automated-only permissions. "
            "Interactive admin operations suggest misuse or compromise."
        ),
        "fn": lambda u, evs: (
            u["privilege_level"] == "service-account"
            and any(e["action"] == "admin_operation" for e in evs)
        ),
    },
    {
        "name": "DOMINANT_AFTER_HOURS",
        "description": (
            "More than 70% of the user's events occur outside business hours. "
            "This is a strong behavioral anomaly for non-service accounts."
        ),
        "fn": lambda u, evs: (
            u["privilege_level"] != "service-account"
            and _after_hours_ratio(evs) > 0.70
        ),
    },
    {
        "name": "HIGH_FAIL_RATIO",
        "description": (
            "More than 40% of the user's events have status=failure. "
            "Elevated failure rate suggests probing, misconfigured access, or credential issues."
        ),
        "fn": lambda u, evs: (
            len(evs) >= 3
            and (sum(1 for e in evs if e["status"] == "failure") / len(evs)) > 0.40
        ),
    },
    {
        "name": "SOD_ADMIN_AND_EXPORT",
        "description": (
            "User performed both admin_operation AND export_data on high-sensitivity resources. "
            "This violates separation of duties — the same person should not administer "
            "and export sensitive data."
        ),
        "fn": lambda u, evs: (
            any(e["action"] == "admin_operation" for e in evs)
            and any(
                e["action"] == "export_data" and e["resource_sensitivity"] == "high"
                for e in evs
            )
        ),
    },
]

# ── Load data ──────────────────────────────────────────────────────────────────

def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_profiles() -> list[dict]:
    if not PROFILES_JSON.exists():
        return []
    with open(PROFILES_JSON, encoding="utf-8") as f:
        return json.load(f)


# ── Core evaluation ────────────────────────────────────────────────────────────

def build_ground_truth(
    users: list[dict],
    events: list[dict],
) -> dict[str, dict]:
    """
    Applies all RULES to each user and returns a dict keyed by user_id:
    {
        is_anomaly: bool,
        triggered_rules: list[str],
    }
    """
    user_events: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        user_events[e["user_id"]].append(e)

    ground_truth: dict[str, dict] = {}
    for user in users:
        uid = user["user_id"]
        evs = user_events.get(uid, [])
        triggered = [r["name"] for r in RULES if r["fn"](user, evs)]
        ground_truth[uid] = {
            "is_anomaly": len(triggered) > 0,
            "triggered_rules": triggered,
        }
    return ground_truth


def compute_metrics(
    y_true: list[int],
    y_pred: list[int],
) -> dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    accuracy  = (tp + tn) / len(y_true) if y_true else 0.0

    return {
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def threshold_sweep(
    profiles: list[dict],
    ground_truth: dict[str, dict],
    thresholds: list[int] | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = [30, 35, 40, 50, 60, 70, 80]

    results = []
    for t in thresholds:
        y_true, y_pred = [], []
        for p in profiles:
            uid = p["user_id"]
            if uid not in ground_truth:
                continue
            y_true.append(1 if ground_truth[uid]["is_anomaly"] else 0)
            y_pred.append(1 if float(p.get("risk_score", 0) or 0) >= t else 0)

        metrics = compute_metrics(y_true, y_pred)
        results.append({"threshold": t, **metrics})
    return results


# ── Reporting ──────────────────────────────────────────────────────────────────

def print_divider(char="─", width=62):
    print(char * width)


def print_section(title: str):
    print()
    print_divider("═")
    print(f"  {title}")
    print_divider("═")


def run_evaluation():
    print_section("IDENTITY ANOMALY DETECTION — SELF EVALUATION")

    # ── Load ──
    if not USERS_CSV.exists():
        print(f"ERROR: {USERS_CSV} not found. Run from the backend/ directory.")
        return
    if not PROFILES_JSON.exists():
        print("ERROR: data/user_profiles.json not found.")
        print("Start the backend and let the pipeline run first, then re-run this script.")
        return

    users    = load_csv(USERS_CSV)
    events   = load_csv(EVENTS_CSV)
    profiles = load_profiles()

    print(f"\n  Users loaded      : {len(users):>6,}")
    print(f"  Events loaded     : {len(events):>6,}")
    print(f"  Profiles scored   : {len(profiles):>6,}")

    if not profiles:
        print("\n  No profiles found. Run the pipeline first.")
        return

    # ── Ground truth ──
    print_section("GROUND TRUTH RULES")
    ground_truth = build_ground_truth(users, events)

    rule_counts: dict[str, int] = defaultdict(int)
    for gt in ground_truth.values():
        for r in gt["triggered_rules"]:
            rule_counts[r] += 1

    n_anomalous = sum(1 for gt in ground_truth.values() if gt["is_anomaly"])
    n_normal    = len(ground_truth) - n_anomalous

    for rule in RULES:
        cnt = rule_counts.get(rule["name"], 0)
        print(f"\n  [{rule['name']}]")
        print(f"    {rule['description']}")
        print(f"    Fires on: {cnt} users")

    print()
    print_divider()
    print(f"  Total anomalous users (any rule fired) : {n_anomalous}")
    print(f"  Total normal users                     : {n_normal}")
    print(f"  Anomaly prevalence                     : {100*n_anomalous/len(ground_truth):.1f}%")
    print_divider()

    # ── Threshold sweep ──
    print_section("PRECISION / RECALL / F1 AT DIFFERENT THRESHOLDS")
    print(f"\n  {'Threshold':>10} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Accuracy':>10} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}")
    print_divider()

    sweep = threshold_sweep(profiles, ground_truth)
    best  = max(sweep, key=lambda x: x["f1"])

    for row in sweep:
        marker = " ◄ BEST F1" if row["threshold"] == best["threshold"] else ""
        print(
            f"  {row['threshold']:>10} "
            f"{row['precision']:>10.3f} "
            f"{row['recall']:>8.3f} "
            f"{row['f1']:>8.3f} "
            f"{row['accuracy']:>10.3f} "
            f"{row['tp']:>5} "
            f"{row['fp']:>5} "
            f"{row['fn']:>5} "
            f"{row['tn']:>5}"
            f"{marker}"
        )

    # ── Confusion matrix at best threshold ──
    print_section(f"CONFUSION MATRIX AT THRESHOLD {best['threshold']}")
    tp, fp, fn, tn = best["tp"], best["fp"], best["fn"], best["tn"]
    print(f"""
                   PREDICTED
                   Anomaly    Normal
  ACTUAL Anomaly  │  {tp:>4}    │  {fn:>4}   │
         Normal   │  {fp:>4}    │  {tn:>4}   │
    """)
    print(f"  False Positive Rate : {100*fp/(fp+tn):.1f}%  (normal users wrongly flagged)")
    print(f"  False Negative Rate : {100*fn/(fn+tp):.1f}%  (anomalies missed)")

    # ── Score distribution ──
    print_section("RISK SCORE DISTRIBUTION (YOUR MODEL)")
    scores = [float(p.get("risk_score", 0) or 0) for p in profiles]
    buckets = {"0-20": 0, "20-40": 0, "40-60": 0, "60-80": 0, "80-100": 0}
    for s in scores:
        if s < 20:   buckets["0-20"]   += 1
        elif s < 40: buckets["20-40"]  += 1
        elif s < 60: buckets["40-60"]  += 1
        elif s < 80: buckets["60-80"]  += 1
        else:        buckets["80-100"] += 1

    for bucket, cnt in buckets.items():
        bar = "█" * int(cnt / max(buckets.values()) * 30)
        print(f"  {bucket:>8}  {bar:<32} {cnt}")

    avg_score = sum(scores) / len(scores) if scores else 0
    print(f"\n  Average risk score : {avg_score:.1f}")
    print(f"  Max risk score     : {max(scores):.1f}")
    print(f"  Min risk score     : {min(scores):.1f}")

    # ── Feedback loop check ──
    feedback_path = DATA_DIR / "feedback.json"
    if feedback_path.exists():
        print_section("FEEDBACK LOOP STATUS")
        with open(feedback_path) as f:
            feedback = json.load(f)
        suppressed = sum(1 for v in feedback.values() if isinstance(v, dict) and v.get("suppressed"))
        print(f"  Total feedback entries : {len(feedback)}")
        print(f"  Suppressed (FP marked) : {suppressed}")
        if len(feedback) >= 5:
            print("  ✓ Enough feedback to influence calibration (feedback_model active)")
        else:
            print("  ✗ Not enough feedback yet — calibration is in cold-start mode")

    # ── Save results ──
    output = {
        "summary": {
            "total_users":   len(users),
            "total_events":  len(events),
            "n_anomalous_gt": n_anomalous,
            "n_normal_gt":    n_normal,
            "anomaly_prevalence_pct": round(100 * n_anomalous / len(ground_truth), 2),
        },
        "rule_counts": dict(rule_counts),
        "threshold_sweep": sweep,
        "best_threshold": best,
        "score_distribution": buckets,
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)

    print_section("SUMMARY")
    print(f"  Best threshold : {best['threshold']}")
    print(f"  Precision      : {best['precision']:.3f}")
    print(f"  Recall         : {best['recall']:.3f}")
    print(f"  F1 Score       : {best['f1']:.3f}")
    print(f"  Accuracy       : {best['accuracy']:.3f}")
    print(f"\n  Full results saved to: {OUTPUT_JSON}")
    print()


if __name__ == "__main__":
    run_evaluation()
