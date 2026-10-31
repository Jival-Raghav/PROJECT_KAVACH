"""
backend/posture/score.py — Enterprise Identity Hygiene Score Engine.

Calculates an overall Identity Hygiene Score (0-100, higher = healthier)
from 9 weighted subscores with automatic dynamic reweighting for missing telemetry:
  1. orphaned_accounts (weight 15)
  2. leaver_active (weight 20)
  3. dormant_privileged (weight 12)
  4. privilege_creep (weight 10)
  5. sod_violations (weight 15)
  6. mfa_coverage (weight 10)
  7. service_account_ownership (weight 8)
  8. shared_accounts (weight 5)
  9. blast_radius_p95 (weight 5)
"""
from __future__ import annotations

from typing import Any
import numpy as np

from core.models import CanonicalBundle
from graph.build import build_identity_graph
from graph.blast import compute_blast_radius
from graph.toxic import detect_toxic_combinations
from resolve.classify import classify_accounts

DEFAULT_WEIGHTS = {
    "orphaned_accounts": 15.0,
    "leaver_active": 20.0,
    "dormant_privileged": 12.0,
    "privilege_creep": 10.0,
    "sod_violations": 15.0,
    "mfa_coverage": 10.0,
    "service_account_ownership": 8.0,
    "shared_accounts": 5.0,
    "blast_radius_p95": 5.0,
}


def calculate_identity_hygiene_score(
    bundle: CanonicalBundle,
    weights_override: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Computes hygiene score (0-100), active subscores, top-5 negative drivers,
    and insurer exposure indicator.
    """
    weights = dict(weights_override or DEFAULT_WEIGHTS)
    subscores: dict[str, dict[str, Any]] = {}

    classified = classify_accounts(bundle.accounts, bundle.identities, [], bundle.events)
    g = build_identity_graph(bundle)
    toxic_findings = detect_toxic_combinations(bundle, g)

    total_accounts = max(1, len(bundle.accounts))
    total_identities = max(1, len(bundle.identities))

    # 1. Orphaned accounts: % active accounts without owner (0 orphans = 100 score)
    orphans = [a for a in classified if a.classification == "orphaned"]
    orphan_pct = len(orphans) / total_accounts
    s_orphan = max(0.0, 100.0 - (orphan_pct * 100.0 * 2.5))
    subscores["orphaned_accounts"] = {
        "score": round(s_orphan, 1),
        "count": len(orphans),
        "percentage": round(orphan_pct * 100, 1),
        "explanation": f"{len(orphans)} unowned/orphaned accounts detected ({round(orphan_pct * 100, 1)}% of inventory).",
    }

    # 2. Leaver-active accounts: count of terminated-but-active accounts
    leavers = [a for a in classified if a.classification == "leaver_active"]
    leaver_deduction = min(100.0, len(leavers) * 30.0)
    s_leaver = max(0.0, 100.0 - leaver_deduction)
    subscores["leaver_active"] = {
        "score": round(s_leaver, 1),
        "count": len(leavers),
        "explanation": f"{len(leavers)} active accounts belonging to terminated personnel.",
    }

    # 3. Dormant privileged accounts
    admin_acc_ids = {a.account_id for a in bundle.accounts if a.privilege_level == "admin"}
    dormant = [a for a in classified if a.classification == "dormant" and a.account_id in admin_acc_ids]
    dormant_pct = len(dormant) / max(1, len(admin_acc_ids))
    s_dormant = max(0.0, 100.0 - (dormant_pct * 100.0))
    subscores["dormant_privileged"] = {
        "score": round(s_dormant, 1),
        "count": len(dormant),
        "explanation": f"{len(dormant)} privileged accounts inactive > 30 days.",
    }

    # 4. Privilege creep (outliers relative to peers)
    ent_counts = {}
    for ent in bundle.entitlements:
        ent_counts[ent.account_id] = ent_counts.get(ent.account_id, 0) + 1
    counts_list = list(ent_counts.values()) or [0]
    p90 = np.percentile(counts_list, 90) if counts_list else 10
    creep_count = sum(1 for c in counts_list if c > p90 and c > 5)
    creep_pct = creep_count / total_accounts
    s_creep = max(0.0, 100.0 - (creep_pct * 100.0 * 2.0))
    subscores["privilege_creep"] = {
        "score": round(s_creep, 1),
        "count": creep_count,
        "explanation": f"{creep_count} accounts exceed 90th percentile privilege threshold ({int(p90)} entitlements).",
    }

    # 5. Separation of Duties violations
    sod_users = {f["identity_id"] for f in toxic_findings}
    sod_pct = len(sod_users) / total_identities
    s_sod = max(0.0, 100.0 - (sod_pct * 100.0 * 3.0))
    subscores["sod_violations"] = {
        "score": round(s_sod, 1),
        "count": len(sod_users),
        "explanation": f"{len(sod_users)} identities possess conflicting toxic/SoD privilege combinations.",
    }

    # 6. MFA coverage on privileged accounts
    priv_accounts = [a for a in bundle.accounts if a.privilege_level == "admin"]
    if priv_accounts and any(a.mfa_enabled is not None for a in priv_accounts):
        mfa_enabled_count = sum(1 for a in priv_accounts if a.mfa_enabled is True)
        mfa_pct = mfa_enabled_count / max(1, len(priv_accounts))
        s_mfa = mfa_pct * 100.0
        subscores["mfa_coverage"] = {
            "score": round(s_mfa, 1),
            "percentage": round(mfa_pct * 100, 1),
            "explanation": f"{round(mfa_pct * 100, 1)}% MFA enforcement rate on privileged administrator accounts.",
        }
    else:
        # Gracefully drop MFA coverage weight if telemetry is unmapped
        del weights["mfa_coverage"]

    # 7. Service account ownership
    service_accs = [a for a in bundle.accounts if a.account_type == "service"]
    if service_accs:
        # Check if service account has mapped owner or custodian
        owned_svcs = [a for a in service_accs if a.employee_id_hint or a.email]
        svc_pct = len(owned_svcs) / max(1, len(service_accs))
        s_svc = svc_pct * 100.0
        subscores["service_account_ownership"] = {
            "score": round(s_svc, 1),
            "percentage": round(svc_pct * 100, 1),
            "explanation": f"{round(svc_pct * 100, 1)}% of service accounts have verified human custodians.",
        }
    else:
        del weights["service_account_ownership"]

    # 8. Shared / generic accounts
    shared_accs = [a for a in bundle.accounts if a.account_type == "shared"]
    s_shared = max(0.0, 100.0 - (len(shared_accs) * 15.0))
    subscores["shared_accounts"] = {
        "score": round(s_shared, 1),
        "count": len(shared_accs),
        "explanation": f"{len(shared_accs)} generic/shared accounts detected without individual attribution.",
    }

    # 9. Blast radius p95 across accounts
    sample_accs = bundle.accounts[:30]
    blast_scores = [compute_blast_radius(g, f"account:{a.account_id}")["blast_score"] for a in sample_accs]
    p95_blast = float(np.percentile(blast_scores, 95)) if blast_scores else 20.0
    s_blast = max(0.0, 100.0 - p95_blast)
    subscores["blast_radius_p95"] = {
        "score": round(s_blast, 1),
        "p95_score": round(p95_blast, 1),
        "explanation": f"95th percentile access blast radius is {round(p95_blast, 1)}/100.",
    }

    # Dynamic Weight Normalization
    total_active_weight = sum(weights.values())
    overall_score = 0.0
    drivers = []

    for name, w in weights.items():
        score_val = subscores[name]["score"]
        norm_weight = (w / total_active_weight) * 100.0
        weighted_contribution = (score_val / 100.0) * norm_weight
        overall_score += weighted_contribution

        deduction = (100.0 - score_val) * (norm_weight / 100.0)
        drivers.append({
            "subscore": name,
            "deduction_points": round(deduction, 1),
            "current_score": score_val,
            "weight_pct": round(norm_weight, 1),
            "explanation": subscores[name]["explanation"],
        })

    # Top-5 negative drivers (largest deductions first)
    drivers.sort(key=lambda d: d["deduction_points"], reverse=True)
    top_drivers = [d for d in drivers if d["deduction_points"] > 0][:5]

    final_score = round(max(0.0, min(100.0, overall_score)), 1)

    # Insurer exposure indicator (indicative, not actuarial)
    exposure_multiplier = max(0.1, round((1.0 - (final_score / 100.0)) * (p95_blast / 100.0) * 10.0, 2))
    exposure_tier = "LOW" if exposure_multiplier < 1.5 else "ELEVATED" if exposure_multiplier < 3.5 else "CRITICAL"

    return {
        "identity_hygiene_score": final_score,
        "grade": "A" if final_score >= 85 else "B" if final_score >= 70 else "C" if final_score >= 50 else "F",
        "subscores": subscores,
        "top_drivers": top_drivers,
        "active_weights": {k: round((v / total_active_weight) * 100, 1) for k, v in weights.items()},
        "insurer_exposure": {
            "exposure_index": exposure_multiplier,
            "tier": exposure_tier,
            "label": "Indicative Security Exposure Index (Illustrative — Not Actuarial)",
            "rationale": f"Derived from {round(p95_blast, 1)} blast reachability and {final_score}/100 hygiene posture.",
        },
    }
