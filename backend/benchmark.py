"""
benchmark.py — Latency and load testing for the Identity Sprawl Detection system.

Tests two things:
  1. Pipeline stage timing at 300 users (real data) and 10k / 100k users (synthetic scale)
  2. API endpoint latency (requires backend running on localhost:8000)

Usage:
    cd backend

    # Stage 1 — pipeline benchmarks only (no server needed):
    python benchmark.py --pipeline

    # Stage 2 — API benchmarks only (start backend first):
    python benchmark.py --api

    # Both:
    python benchmark.py

Outputs:
    - Console table with timings
    - Saves results to benchmark_results.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR      = Path(__file__).parent / "data"
USERS_CSV     = DATA_DIR / "identity_users.csv"
EVENTS_CSV    = DATA_DIR / "identity_events.csv"
OUTPUT_JSON   = Path(__file__).parent / "benchmark_results.json"
BASE_URL      = "http://localhost:8000"

# ── Helpers ────────────────────────────────────────────────────────────────────

def print_divider(char="─", width=66):
    print(char * width)


def print_section(title: str):
    print()
    print_divider("═")
    print(f"  {title}")
    print_divider("═")


class Timer:
    def __init__(self):
        self._start = None
        self.elapsed = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.elapsed = time.perf_counter() - self._start


def fmt_time(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    return f"{seconds:.2f}s"


def percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


# ── Synthetic data generation ──────────────────────────────────────────────────

def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def generate_synthetic_users(real_users: list[dict], n: int) -> list[dict]:
    """
    Scales real users to n by repeating and perturbing numeric fields.
    Each synthetic user gets a unique user_id.
    """
    priv_levels  = ["user", "power-user", "admin", "service-account"]
    departments  = list({u["department"] for u in real_users})
    systems_pool = ["AD", "AWS_IAM", "GCP", "PROD_DB", "SIEM", "HRIS",
                    "EMAIL", "VPN", "Salesforce", "Admin_Console"]

    synthetic = []
    for i in range(n):
        base = real_users[i % len(real_users)]
        synthetic.append({
            **base,
            "user_id":        f"SYNTH{i:07d}",
            "username":       f"user_{i}@company.com",
            "email":          f"user_{i}@company.com",
            "days_inactive":  str(random.randint(0, 59)),
            "privilege_level": random.choice(priv_levels),
            "department":     random.choice(departments),
            "systems_access": "|".join(random.sample(systems_pool, k=random.randint(1, 4))),
            "is_active":      "true",
        })
    return synthetic


def generate_synthetic_events(user_ids: list[str], n: int) -> list[dict]:
    """
    Generates n synthetic events distributed randomly across user_ids.
    """
    actions      = ["login", "export_data", "admin_operation", "api_call", "file_access", "sql_query"]
    resources    = ["PROD_DB", "SIEM", "HRIS", "Admin_Console", "Data_Lake", "EMAIL", "GL_System"]
    sensitivities = ["low", "medium", "high"]
    time_classes  = ["business_hours", "unusual_hours", "night", "weekend"]
    statuses      = ["success", "failure"]

    events = []
    for i in range(n):
        uid = random.choice(user_ids)
        events.append({
            "timestamp":           f"2025-{random.randint(4,12):02d}-{random.randint(1,28):02d} "
                                   f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:00",
            "user_id":             uid,
            "username":            f"user_{uid}",
            "action":              random.choice(actions),
            "resource":            random.choice(resources),
            "resource_sensitivity": random.choice(sensitivities),
            "status":              random.choice(statuses),
            "source_ip":           f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            "time_classification": random.choice(time_classes),
        })
    return events


# ── Pipeline benchmarks ────────────────────────────────────────────────────────

def bench_pipeline(scale_label: str, users: list[dict], events: list[dict]) -> dict:
    """
    Times each pipeline stage against the given users/events lists.
    Imports backend modules directly — must be run from backend/ directory.
    """
    from schemas import make_stub_profile
    from models.isolation_forest import score_users
    from models.kmeans_events import cluster_events, assign_cluster_to_users
    from models.org_anomaly import detect_org_anomalies
    from models.sod_violations import check_sod_violations
    from models.compliance import compute_compliance_gaps

    timings = {}
    n_users  = len(users)
    n_events = len(events)

    print(f"\n  Scale: {scale_label}  ({n_users:,} users / {n_events:,} events)")
    print_divider()

    # 1. make_stub_profile
    with Timer() as t:
        profiles = [make_stub_profile(u) for u in users]
    timings["make_stub_profiles"] = t.elapsed
    print(f"  {'make_stub_profile (×' + str(n_users) + ')':<42} {fmt_time(t.elapsed):>8}")

    # 2. feature engineering + IsolationForest scoring
    with Timer() as t:
        profiles = score_users(profiles, events)
    timings["isolation_forest_scoring"] = t.elapsed
    print(f"  {'feature_engineering + IsolationForest':<42} {fmt_time(t.elapsed):>8}")

    # 3. KMeans on events
    with Timer() as t:
        event_clusters = cluster_events(events)
    timings["kmeans_events"] = t.elapsed
    print(f"  {'cluster_events (KMeans)':<42} {fmt_time(t.elapsed):>8}")

    # 4. Assign clusters to users
    with Timer() as t:
        profiles = assign_cluster_to_users(profiles, event_clusters)
    timings["assign_clusters"] = t.elapsed
    print(f"  {'assign_cluster_to_users':<42} {fmt_time(t.elapsed):>8}")

    # 5. Org anomaly
    with Timer() as t:
        profiles = detect_org_anomalies(profiles)
    timings["org_anomaly"] = t.elapsed
    print(f"  {'detect_org_anomalies':<42} {fmt_time(t.elapsed):>8}")

    # 6. SoD violations (per user, potentially slow at scale)
    user_events_map: dict[str, list] = defaultdict(list)
    for e in events:
        user_events_map[e["user_id"]].append(e)

    with Timer() as t:
        for p in profiles:
            check_sod_violations(p, user_events_map.get(p["user_id"], []))
    timings["sod_violations"] = t.elapsed
    print(f"  {'sod_violations (all users)':<42} {fmt_time(t.elapsed):>8}")

    # 7. Compliance gaps
    with Timer() as t:
        for p in profiles:
            compute_compliance_gaps(p)
    timings["compliance_gaps"] = t.elapsed
    print(f"  {'compliance_gaps (all users)':<42} {fmt_time(t.elapsed):>8}")

    total = sum(timings.values())
    timings["total"] = total
    print_divider()
    print(f"  {'TOTAL PIPELINE TIME':<42} {fmt_time(total):>8}")
    print(f"  {'Throughput':<42} {n_users / total:>6.0f} users/sec")

    return {
        "scale": scale_label,
        "n_users": n_users,
        "n_events": n_events,
        "timings_seconds": {k: round(v, 4) for k, v in timings.items()},
        "throughput_users_per_sec": round(n_users / total, 1),
    }


# ── API benchmarks ─────────────────────────────────────────────────────────────

def bench_api() -> dict:
    """
    Hits each API endpoint repeatedly and reports median / p95 latency.
    Requires the backend to be running on BASE_URL.
    """
    try:
        import urllib.request
        import urllib.error
    except ImportError:
        print("  urllib not available")
        return {}

    def get(path: str) -> tuple[int, float]:
        url = f"{BASE_URL}{path}"
        start = time.perf_counter()
        try:
            req = urllib.request.urlopen(url, timeout=10)
            body = req.read()
            elapsed = time.perf_counter() - start
            return req.status, elapsed
        except urllib.error.URLError as e:
            elapsed = time.perf_counter() - start
            return 0, elapsed

    # Check server is up
    status, _ = get("/status")
    if status == 0:
        print(f"\n  ERROR: Cannot reach {BASE_URL}")
        print("  Start the backend first: uvicorn main:app --reload --port 8000")
        return {}

    print(f"\n  Backend is reachable at {BASE_URL}")
    print_divider()

    endpoints = [
        ("/status",          "GET /status",          20),
        ("/users/risks",     "GET /users/risks",      10),
        ("/org-anomalies",   "GET /org-anomalies",    10),
        ("/clusters/summary","GET /clusters/summary", 10),
        ("/stats",           "GET /stats",            15),
    ]

    # Get a real user_id for single-user endpoints
    _, _ = get("/users/risks")
    try:
        req = urllib.request.urlopen(f"{BASE_URL}/users/risks", timeout=10)
        users_data = json.loads(req.read())
        if users_data:
            sample_uid = users_data[0]["user_id"]
            endpoints.append((
                f"/users/{sample_uid}",
                f"GET /users/{{user_id}}",
                15,
            ))
            endpoints.append((
                f"/users/{sample_uid}/breach-simulation",
                "GET /users/{id}/breach-simulation",
                10,
            ))
    except Exception:
        pass

    print(f"  {'Endpoint':<38} {'Median':>8} {'p95':>8} {'Min':>8} {'Max':>8}  {'N':>4}")
    print_divider()

    api_results = []
    for path, label, n_calls in endpoints:
        times = []
        for _ in range(n_calls):
            _, elapsed = get(path)
            times.append(elapsed)
            time.sleep(0.05)  # small pause to avoid overwhelming the server

        med  = percentile(times, 50)
        p95  = percentile(times, 95)
        mn   = min(times)
        mx   = max(times)

        print(f"  {label:<38} {fmt_time(med):>8} {fmt_time(p95):>8} {fmt_time(mn):>8} {fmt_time(mx):>8}  {n_calls:>4}")

        api_results.append({
            "endpoint": label,
            "n_calls":  n_calls,
            "median_ms": round(med * 1000, 1),
            "p95_ms":    round(p95 * 1000, 1),
            "min_ms":    round(mn  * 1000, 1),
            "max_ms":    round(mx  * 1000, 1),
        })

    return {"endpoints": api_results}


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline", action="store_true", help="Run pipeline benchmarks only")
    parser.add_argument("--api",      action="store_true", help="Run API benchmarks only")
    args = parser.parse_args()

    # Default: run both
    run_pipeline = args.pipeline or (not args.pipeline and not args.api)
    run_api      = args.api      or (not args.pipeline and not args.api)

    results = {}

    # ── Pipeline benchmarks ──
    if run_pipeline:
        print_section("PIPELINE STAGE BENCHMARKS")

        if not USERS_CSV.exists():
            print(f"  ERROR: {USERS_CSV} not found. Run from backend/ directory.")
            sys.exit(1)

        real_users  = load_csv(USERS_CSV)
        real_events = load_csv(EVENTS_CSV)

        pipeline_results = []

        # Real data (300 users)
        r = bench_pipeline("300 users (real data)", real_users, real_events)
        pipeline_results.append(r)

        # 10k synthetic
        print()
        users_10k  = generate_synthetic_users(real_users, 10_000)
        events_10k = generate_synthetic_events([u["user_id"] for u in users_10k], 30_000)
        r = bench_pipeline("10,000 users (synthetic)", users_10k, events_10k)
        pipeline_results.append(r)

        # 100k synthetic
        print()
        print("  Generating 100k synthetic users (this takes a moment)...")
        users_100k  = generate_synthetic_users(real_users, 100_000)
        events_100k = generate_synthetic_events([u["user_id"] for u in users_100k], 300_000)
        r = bench_pipeline("100,000 users (synthetic)", users_100k, events_100k)
        pipeline_results.append(r)

        results["pipeline"] = pipeline_results

        # ── Scalability summary ──
        print_section("SCALABILITY SUMMARY")
        print(f"\n  {'Scale':<30} {'Total Time':>12} {'Throughput':>16}")
        print_divider()
        for r in pipeline_results:
            print(
                f"  {r['scale']:<30} "
                f"{fmt_time(r['timings_seconds']['total']):>12} "
                f"{r['throughput_users_per_sec']:>12.0f} u/s"
            )

        # ── Bottleneck identification ──
        print_section("BOTTLENECK ANALYSIS (100k run)")
        last = pipeline_results[-1]["timings_seconds"]
        total = last["total"]
        stages = [(k, v) for k, v in last.items() if k != "total"]
        stages.sort(key=lambda x: -x[1])
        print(f"\n  {'Stage':<38} {'Time':>8} {'% of total':>12}")
        print_divider()
        for stage, t in stages:
            pct = 100 * t / total if total > 0 else 0
            bar = "█" * int(pct / 3)
            print(f"  {stage:<38} {fmt_time(t):>8}  {pct:>5.1f}%  {bar}")

    # ── API benchmarks ──
    if run_api:
        print_section("API ENDPOINT LATENCY BENCHMARKS")
        api_results = bench_api()
        if api_results:
            results["api"] = api_results

    # ── Save ──
    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)

    print_section("DONE")
    print(f"  Results saved to: {OUTPUT_JSON}")
    print()


if __name__ == "__main__":
    main()
