"""scripts/bench_resolution.py
Identity Resolution Benchmark for ISPAD v2.

Evaluates:
1. Pair Precision (>= 0.95) & Recall (>= 0.90) across planted aliases, typos, nicknames, and inversions.
2. Invariant: 0 merges across conflicting employee IDs.
3. Leaver-Active detection recall (>= 0.95).
4. Orphan detection recall (>= 0.95).
5. Output benchmark results to reports/resolution.md.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure backend is on sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "backend"))

from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEvent,
    CanonicalIdentity,
)
from resolve.engine import run_identity_resolution


def build_benchmark_dataset() -> tuple[CanonicalBundle, dict[str, set[str]], set[str], set[str], list[tuple[str, str]]]:
    """Build synthetic benchmark dataset with planted positive pairs, negative pairs,

    leaver accounts, orphan accounts, dormant accounts, and service accounts.

    Returns:
    - bundle: CanonicalBundle
    - ground_truth_clusters: dict mapping canonical person_id -> set of record_ids (id:... or acc:...)
    - planted_leaver_acc_ids: set of account IDs planted as leaver_active
    - planted_orphan_acc_ids: set of account IDs planted as orphaned
    - conflicting_emp_pairs: list of (rec_a, rec_b) that have high name similarity but different employee IDs
    """
    now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)

    identities: list[CanonicalIdentity] = []
    accounts: list[CanonicalAccount] = []
    events: list[CanonicalEvent] = []

    ground_truth_clusters: dict[str, set[str]] = {}
    planted_leaver_acc_ids: set[str] = set()
    planted_orphan_acc_ids: set[str] = set()
    conflicting_emp_pairs: list[tuple[str, str]] = []

    # ── Group A: Deterministic & Fuzzy Positive Human Identites (20 people, ~50 accounts) ──
    human_specs = [
        # (emp_id, full_name, email, dept, title, accounts_spec)
        ("E1001", "Robert Davis", "robert.davis@corp.com", "Engineering", "Staff Engineer", [
            ("acc_rd_1", "okta", "rdavis", "robert.davis@corp.com", "E1001"),
            ("acc_rd_2", "aws", "bob.davis", "bdavis@corp.com", None),  # Nickname
            ("acc_rd_3", "github", "rdavis99", None, None),  # Trailing digits
        ]),
        ("E1002", "Elizabeth Montgomery", "elizabeth.m@corp.com", "Finance", "VP Finance", [
            ("acc_em_1", "okta", "emontgomery", "elizabeth.m@corp.com", "E1002"),
            ("acc_em_2", "sap", "beth.montgomery", "bmontgomery@corp.com", None),  # Nickname
            ("acc_em_3", "salesforce", "e_montgomery", None, None),
        ]),
        ("E1003", "William Harrison", "wharrison@corp.com", "Sales", "Account Exec", [
            ("acc_wh_1", "okta", "wharrison", "wharrison@corp.com", "E1003"),
            ("acc_wh_2", "crm", "bill.harrison", "bill.harrison@corp.com", None),  # Nickname
        ]),
        ("E1004", "Alexander Wright", "alex.wright@corp.com", "Security", "SecOps Lead", [
            ("acc_aw_1", "okta", "awright", "alex.wright@corp.com", "E1004"),
            ("acc_aw_2", "crowdstrike", "alexandre.wright", None, None),  # Typo/variant
        ]),
        ("E1005", "René Müller", "rene.muller@corp.com", "Engineering", "Backend Dev", [
            ("acc_rm_1", "okta", "rmuller", "rene.muller@corp.com", "E1005"),
            ("acc_rm_2", "gitlab", "rene.mueller", "rmueller@corp.com", None),  # Accent/variant
        ]),
        ("E1006", "David Miller", "david.miller@corp.com", "IT", "SysAdmin", [
            ("acc_dm_1", "okta", "dmiller", "david.miller@corp.com", "E1006"),
            ("acc_dm_2", "active_directory", "millerd", "millerd@corp.com", None),
        ]),
        ("E1007", "James Wilson", "james.wilson@corp.com", "Marketing", "Marketing Mgr", [
            ("acc_jw_1", "okta", "jwilson", "james.wilson@corp.com", "E1007"),
            ("acc_jw_2", "hubspot", "jim.wilson", "jim.wilson@corp.com", None),  # Nickname
        ]),
        ("E1008", "Katherine Johnson", "kjohnson@corp.com", "Research", "Research Scientist", [
            ("acc_kj_1", "okta", "kjohnson", "kjohnson@corp.com", "E1008"),
            ("acc_kj_2", "jupyter", "kate.johnson", "kate.johnson@corp.com", None),  # Nickname
        ]),
        ("E1009", "Thomas Anderson", "tanderson@corp.com", "Engineering", "Software Engineer", [
            ("acc_ta_1", "okta", "tanderson", "tanderson@corp.com", "E1009"),
            ("acc_ta_2", "jira", "tom.anderson", "tom.anderson@corp.com", None),  # Nickname
        ]),
        ("E1010", "Margaret Hamilton", "mhamilton@corp.com", "Engineering", "Distinguished Engineer", [
            ("acc_mh_1", "okta", "mhamilton", "mhamilton@corp.com", "E1010"),
            ("acc_mh_2", "github", "peggy.hamilton", "peggy.h@corp.com", None),  # Nickname
        ]),
        ("E1011", "Richard Feynman", "rfeynman@corp.com", "Research", "Scientist", [
            ("acc_rf_1", "okta", "rfeynman", "rfeynman@corp.com", "E1011"),
            ("acc_rf_2", "slack", "dick.feynman", "dick.feynman@corp.com", None),  # Nickname
        ]),
        ("E1012", "Michael Chen", "mchen@corp.com", "Product", "Product Lead", [
            ("acc_mc_1", "okta", "mchen", "mchen@corp.com", "E1012"),
            ("acc_mc_2", "notion", "mike.chen", "mike.chen@corp.com", None),  # Nickname
        ]),
        ("E1013", "Christopher Nolan", "cnolan@corp.com", "Design", "Creative Director", [
            ("acc_cn_1", "okta", "cnolan", "cnolan@corp.com", "E1013"),
            ("acc_cn_2", "figma", "chris.nolan", "chris.nolan@corp.com", None),  # Nickname
        ]),
        ("E1014", "Jennifer Lawrence", "jlawrence@corp.com", "HR", "People Ops", [
            ("acc_jl_1", "okta", "jlawrence", "jlawrence@corp.com", "E1014"),
            ("acc_jl_2", "workday", "jen.lawrence", "jen.lawrence@corp.com", None),  # Nickname
        ]),
        ("E1015", "Anthony Stark", "astark@corp.com", "Engineering", "Hardware Lead", [
            ("acc_as_1", "okta", "astark", "astark@corp.com", "E1015"),
            ("acc_as_2", "cad", "tony.stark", "tony.stark@corp.com", None),  # Nickname
        ]),
    ]

    for emp_id, name, email, dept, title, acc_specs in human_specs:
        ident_id = f"id_{emp_id}"
        ident = CanonicalIdentity(
            identity_id=ident_id,
            employee_id=emp_id,
            full_name=name,
            email=email,
            department=dept,
            job_title=title,
            employment_status="active",
        )
        identities.append(ident)

        gt_members = {f"id:{ident_id}"}
        for acc_id, sys_name, uname, uemail, emp_hint in acc_specs:
            acc = CanonicalAccount(
                account_id=acc_id,
                system=sys_name,
                username=uname,
                email=uemail,
                employee_id_hint=emp_hint,
                status="active",
                last_login=(now - timedelta(days=2)).isoformat(),
            )
            accounts.append(acc)
            gt_members.add(f"acc:{acc_id}")

            events.append(
                CanonicalEvent(
                    event_id=f"ev_{acc_id}_1",
                    timestamp=(now - timedelta(days=2)).isoformat(),
                    user_key=uname,
                    action="login",
                    system=sys_name,
                    source_ip="10.0.0.15",
                )
            )

        ground_truth_clusters[emp_id] = gt_members

    # ── Group B: Planted Conflicting Employee IDs (Hard Invariant Test) ────────
    # Two people with same/similar name but DIFFERENT employee IDs: MUST NEVER MERGE!
    id_conf_1 = CanonicalIdentity(
        identity_id="id_E2001",
        employee_id="E2001",
        full_name="Daniel Craig",
        email="daniel.craig@corp.com",
        department="Operations",
    )
    acc_conf_1 = CanonicalAccount(
        account_id="acc_dc_1",
        system="okta",
        username="dcraig",
        email="daniel.craig@corp.com",
        employee_id_hint="E2001",
    )
    id_conf_2 = CanonicalIdentity(
        identity_id="id_E2002",
        employee_id="E2002",
        full_name="Daniel Craig",  # Same exact name!
        email="daniel.craig2@corp.com",
        department="Finance",
    )
    acc_conf_2 = CanonicalAccount(
        account_id="acc_dc_2",
        system="okta",
        username="dcraig2",
        email="daniel.craig2@corp.com",
        employee_id_hint="E2002",
    )
    identities.extend([id_conf_1, id_conf_2])
    accounts.extend([acc_conf_1, acc_conf_2])
    ground_truth_clusters["E2001"] = {"id:id_E2001", "acc:acc_dc_1"}
    ground_truth_clusters["E2002"] = {"id:id_E2002", "acc:acc_dc_2"}
    conflicting_emp_pairs.append(("acc:acc_dc_1", "acc:acc_dc_2"))
    conflicting_emp_pairs.append(("id:id_E2001", "id:id_E2002"))

    # ── Group C: Planted Leaver-Active Accounts (10 cases) ─────────────────────
    for i in range(1, 11):
        emp_id = f"E_LEAVER_{i:02d}"
        term_date = (now - timedelta(days=30 + i * 5)).isoformat()
        ident_id = f"id_{emp_id}"
        ident = CanonicalIdentity(
            identity_id=ident_id,
            employee_id=emp_id,
            full_name=f"Terminated Worker {i}",
            email=f"worker.{i}@corp.com",
            department="Operations",
            employment_status="terminated",
            termination_date=term_date,
        )
        identities.append(ident)

        acc_id = f"acc_leaver_{i}"
        planted_leaver_acc_ids.add(acc_id)

        # 5 cases: active status; 5 cases: post-termination login events
        has_post_term_login = (i % 2 == 0)
        login_date = (now - timedelta(days=5)).isoformat() if has_post_term_login else (now - timedelta(days=40)).isoformat()

        acc = CanonicalAccount(
            account_id=acc_id,
            system="aws" if i % 2 == 0 else "vpn",
            username=f"tworker_{i}",
            email=f"worker.{i}@corp.com",
            employee_id_hint=emp_id,
            status="active",  # Still active in directory!
            last_login=login_date,
        )
        accounts.append(acc)
        ground_truth_clusters[emp_id] = {f"id:{ident_id}", f"acc:{acc_id}"}

        if has_post_term_login:
            events.append(
                CanonicalEvent(
                    event_id=f"ev_leaver_{i}",
                    timestamp=login_date,
                    user_key=f"tworker_{i}",
                    action="login",
                    system=acc.system,
                    source_ip="198.51.100.42",
                )
            )

    # ── Group D: Planted Orphan Accounts (10 cases) ───────────────────────────
    for i in range(1, 11):
        acc_id = f"acc_orphan_{i}"
        planted_orphan_acc_ids.add(acc_id)
        acc = CanonicalAccount(
            account_id=acc_id,
            system="salesforce" if i % 2 == 0 else "jira",
            username=f"ext_consultant_{i}",
            email=f"consultant_{i}@external-vendor.com",
            employee_id_hint=None,  # No HR record
            status="active",
            last_login=(now - timedelta(days=10)).isoformat(),
        )
        accounts.append(acc)

    # ── Group E: Planted Dormant Accounts (5 cases) ───────────────────────────
    for i in range(1, 6):
        acc_id = f"acc_dormant_{i}"
        dormant_date = (now - timedelta(days=120 + i * 10)).isoformat()
        acc = CanonicalAccount(
            account_id=acc_id,
            system="legacy_erp",
            username=f"dormant_user_{i}",
            email=f"dormant_{i}@corp.com",
            status="active",
            last_login=dormant_date,
        )
        accounts.append(acc)

    # ── Group F: Planted Service Accounts (5 cases) ───────────────────────────
    service_names = ["svc_backup_agent", "bot-github-sync", "batch-payroll", "sys-log-forwarder", "api-gateway-daemon"]
    for i, sname in enumerate(service_names, 1):
        acc_id = f"acc_svc_{i}"
        acc = CanonicalAccount(
            account_id=acc_id,
            system="infrastructure",
            username=sname,
            account_type="service",
            status="active",
            last_login=(now - timedelta(hours=1)).isoformat(),
        )
        accounts.append(acc)

    # ── Group G: Planted Shared Accounts (3 cases) ───────────────────────────
    for sname in ["admin", "ops", "root"]:
        acc_id = f"acc_shared_{sname}"
        acc = CanonicalAccount(
            account_id=acc_id,
            system="linux_cluster",
            username=sname,
            account_type="shared",
            status="active",
            last_login=(now - timedelta(hours=2)).isoformat(),
        )
        accounts.append(acc)
        # Sprawling IPs
        for ip_idx, ip_addr in enumerate(["192.168.1.10", "10.50.2.1", "172.16.0.4", "203.0.113.19"]):
            events.append(
                CanonicalEvent(
                    event_id=f"ev_{acc_id}_{ip_idx}",
                    timestamp=(now - timedelta(hours=ip_idx + 1)).isoformat(),
                    user_key=sname,
                    action="sudo_exec",
                    system="linux_cluster",
                    source_ip=ip_addr,
                )
            )

    bundle = CanonicalBundle(
        run_id="bench_resolution_v2",
        identities=identities,
        accounts=accounts,
        events=events,
    )

    return bundle, ground_truth_clusters, planted_leaver_acc_ids, planted_orphan_acc_ids, conflicting_emp_pairs


def run_benchmark() -> dict[str, float | int | bool]:
    print("=" * 70)
    print("ISPAD v2 — Phase 2 Identity Resolution Benchmark")
    print("=" * 70)

    bundle, gt_clusters, planted_leavers, planted_orphans, conflicting_emp_pairs = build_benchmark_dataset()

    print("Generated benchmark dataset:")
    print(f"  • Identities: {len(bundle.identities)}")
    print(f"  • Accounts:   {len(bundle.accounts)}")
    print(f"  • Events:     {len(bundle.events)}")
    print(f"  • Ground truth human clusters: {len(gt_clusters)}")
    print(f"  • Planted leaver accounts:     {len(planted_leavers)}")
    print(f"  • Planted orphan accounts:     {len(planted_orphans)}")

    # Execute Resolution Pipeline
    res = run_identity_resolution(bundle, auto_merge_threshold=0.90, review_threshold=0.70, persist=True)

    # 1. Evaluate Pair Precision and Recall on Ground Truth Positive Clusters
    # Positive pairs are all pairs (u, v) within the same ground-truth cluster
    gt_positive_pairs: set[tuple[str, str]] = set()
    for cluster_members in gt_clusters.values():
        members = sorted(cluster_members)
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                gt_positive_pairs.add((members[i], members[j]))

    # Build predicted clusters: map each record to its GoldenIdentity identity_id
    pred_ident_of_rec: dict[str, str] = {}
    for gid in res.golden_identities:
        if gid.extra.get("hr_backed"):
            pred_ident_of_rec[f"id:{gid.identity_id}"] = gid.identity_id
        for acc_id in gid.linked_account_ids:
            pred_ident_of_rec[f"acc:{acc_id}"] = gid.identity_id

    # Evaluate predicted pairs over genuine input dataset records
    input_records = [f"id:{i.identity_id}" for i in bundle.identities] + [f"acc:{a.account_id}" for a in bundle.accounts]
    tp_pairs = 0
    fp_pairs = 0

    for i in range(len(input_records)):
        for j in range(i + 1, len(input_records)):
            r_a = input_records[i]
            r_b = input_records[j]
            c_a = pred_ident_of_rec.get(r_a)
            c_b = pred_ident_of_rec.get(r_b)
            same_pred = (c_a is not None and c_b is not None and c_a == c_b)

            pair_key = (min(r_a, r_b), max(r_a, r_b))
            is_gt_positive = pair_key in gt_positive_pairs

            if same_pred and is_gt_positive:
                tp_pairs += 1
            elif same_pred and not is_gt_positive:
                fp_pairs += 1

    precision = tp_pairs / (tp_pairs + fp_pairs) if (tp_pairs + fp_pairs) > 0 else 1.0
    recall = tp_pairs / len(gt_positive_pairs) if len(gt_positive_pairs) > 0 else 0.0

    # 2. Evaluate Invariant: Conflicting Employee ID Merges
    conflicts_merged = 0
    for r_a, r_b in conflicting_emp_pairs:
        if r_a in pred_ident_of_rec and r_b in pred_ident_of_rec:
            if pred_ident_of_rec[r_a] == pred_ident_of_rec[r_b]:
                conflicts_merged += 1

    # 3. Evaluate Leaver-Active Detection Recall
    detected_leaver_acc_ids = {
        cl.account_id
        for cl in res.classifications
        if cl.classification == "leaver_active"
    }
    leaver_tp = len(detected_leaver_acc_ids & planted_leavers)
    leaver_recall = leaver_tp / len(planted_leavers) if planted_leavers else 1.0

    # 4. Evaluate Orphan Detection Recall
    detected_orphan_acc_ids = {
        cl.account_id
        for cl in res.classifications
        if cl.classification == "orphaned"
    }
    orphan_tp = len(detected_orphan_acc_ids & planted_orphans)
    orphan_recall = orphan_tp / len(planted_orphans) if planted_orphans else 1.0

    print("-" * 70)
    print(f"Pair Precision:        {precision * 100:.2f}% (Target: >= 95.0%)")
    print(f"Pair Recall:           {recall * 100:.2f}% (Target: >= 90.0%)")
    print(f"Conflicting ID Merges: {conflicts_merged} (Target: 0)")
    print(f"Leaver Recall:         {leaver_recall * 100:.2f}% (Target: >= 95.0%)")
    print(f"Orphan Recall:         {orphan_recall * 100:.2f}% (Target: >= 95.0%)")
    print("-" * 70)

    # Acceptance Checks
    pass_prec = precision >= 0.95
    pass_rec = recall >= 0.90
    pass_conflicts = (conflicts_merged == 0)
    pass_leaver = leaver_recall >= 0.95
    pass_orphan = orphan_recall >= 0.95

    all_passed = all([pass_prec, pass_rec, pass_conflicts, pass_leaver, pass_orphan])

    # Write Markdown Report
    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "resolution.md"

    report_content = f"""# Identity Resolution Benchmark Report (Phase 2)

**Timestamp:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}
**Run ID:** `{bundle.run_id}`
**Overall Status:** {'PASS' if all_passed else 'FAIL'}

---

## 1. Executive Summary

Feature 1b (Identity Resolution Engine) unifies fragmented user accounts across directories, IdPs, and infrastructure into canonical **Golden Identities**, while detecting high-risk credential sprawl (**orphans**, **leaver-active**, **dormant**, **service**, and **shared** accounts).

| Metric | Target | Benchmark Result | Status |
|---|---|---|---|
| **Pair Precision** | $\\ge 95.0\\%$ | **{precision * 100:.2f}%** | {'PASS' if pass_prec else 'FAIL'} |
| **Pair Recall** | $\\ge 90.0\\%$ | **{recall * 100:.2f}%** | {'PASS' if pass_rec else 'FAIL'} |
| **Conflicting Employee ID Merges** | **0** | **{conflicts_merged}** | {'PASS' if pass_conflicts else 'FAIL'} |
| **Leaver-Active Detection Recall** | $\\ge 95.0\\%$ | **{leaver_recall * 100:.2f}%** | {'PASS' if pass_leaver else 'FAIL'} |
| **Orphan Account Detection Recall** | $\\ge 95.0\\%$ | **{orphan_recall * 100:.2f}%** | {'PASS' if pass_orphan else 'FAIL'} |

---

## 2. Hard Invariant Verification: Constrained Union-Find

A core requirement of ISPAD v2 is that records carrying differing non-null employee IDs are **never merged**, regardless of fuzzy name similarity, nickname equivalence, or matching surname.

- **Planted Conflicting ID Pairs Tested:** `{len(conflicting_emp_pairs)}`
- **Merges Allowed:** `0`
- **Refused Merges Recorded in Engine:** `{res.metrics.get('refused_merges_count', 0)}`

---

## 3. Account Sprawl & Security Classifications

| Classification | Count Detected | Risk Level | Description |
|---|---|---|---|
| **Leaver-Active** | `{res.metrics.get('leaver_active_count', 0)}` | Critical | Terminated HR employees retaining active directory logins or post-departure events |
| **Orphaned** | `{res.metrics.get('orphaned_count', 0)}` | High | Active system accounts with no corresponding HR identity |
| **Shared** | `{res.metrics.get('shared_count', 0)}` | High | Generic or concurrent multi-IP/geographic sprawling access |
| **Dormant** | `{res.metrics.get('dormant_count', 0)}` | Medium | Active accounts with no login activity exceeding threshold (90 days) |
| **Service** | `{res.metrics.get('service_count', 0)}` | Medium / Low | Daemons, automated pipelines, and batch service credentials |
| **Standard Human** | `{res.metrics.get('human_count', 0)}` | Low | Verified active employee accounts |

---

## 4. Pipeline Diagnostics

- **Total Canonical Accounts Analyzed:** `{res.metrics.get('total_accounts', 0)}`
- **Total Canonical HR Identities:** `{res.metrics.get('total_hr_identities', 0)}`
- **Golden Identity Clusters Formed:** `{res.metrics.get('golden_identities_count', 0)}`
- **Account Links Generated:** `{res.metrics.get('account_links_count', 0)}`
- **Candidate Pairs Scored (Post-Blocking):** `{res.metrics.get('candidate_pairs_evaluated', 0)}`
- **Review Queue Items (0.70 - 0.90 Band):** `{res.metrics.get('review_queue_count', 0)}`
"""

    report_file.write_text(report_content, encoding="utf-8")
    print(f"Wrote benchmark report to: {report_file}")

    return {
        "precision": precision,
        "recall": recall,
        "conflicts_merged": conflicts_merged,
        "leaver_recall": leaver_recall,
        "orphan_recall": orphan_recall,
        "all_passed": all_passed,
    }


if __name__ == "__main__":
    results = run_benchmark()
    if not results["all_passed"]:
        sys.exit(1)
