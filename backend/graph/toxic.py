"""
backend/graph/toxic.py — Toxic Combinations, Multi-Hop SoD, and Privilege Creep Analysis.

Detects:
1. Multi-hop SoD combinations (identity possessing conflicting entitlements across disparate accounts).
2. Toxic entitlement combinations (e.g. create_vendor + approve_payment).
3. Privilege creep outliers relative to peer median.
4. Unused entitlements (dormant > N days or zero observed activity).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import networkx as nx
from core.models import CanonicalBundle

# Standard toxic entitlement pairs
DEFAULT_TOXIC_PAIRS = [
    ("create_vendor", "approve_payment"),
    ("admin", "billing_admin"),
    ("billing_admin", "refund_processor"),
    ("developer", "deployer"),
    ("auditor", "admin"),
    ("user_admin", "role_admin"),
]


def detect_toxic_combinations(
    bundle: CanonicalBundle,
    g: nx.DiGraph | None = None,
    toxic_pairs: list[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """
    Finds toxic combinations held by the same identity (even across different accounts).
    """
    pairs = toxic_pairs or DEFAULT_TOXIC_PAIRS
    toxic_findings = []

    # Map identity_id -> set of entitlements held across all accounts
    # First map account_id -> identity_id
    id_by_emp_id = {i.employee_id: i.identity_id for i in bundle.identities if i.employee_id}
    id_by_email = {i.email.lower(): i.identity_id for i in bundle.identities if i.email}

    acc_to_identity = {}
    for acc in bundle.accounts:
        matched_id = None
        if acc.employee_id_hint and acc.employee_id_hint in id_by_emp_id:
            matched_id = id_by_emp_id[acc.employee_id_hint]
        elif acc.email and acc.email.lower() in id_by_email:
            matched_id = id_by_email[acc.email.lower()]
        else:
            matched_id = acc.username or acc.account_id
        acc_to_identity[acc.account_id] = matched_id

    # Collect entitlements per identity
    identity_entitlements: dict[str, list[dict[str, Any]]] = {}
    for ent in bundle.entitlements:
        ident = acc_to_identity.get(ent.account_id, "unknown")
        if ident not in identity_entitlements:
            identity_entitlements[ident] = []
        identity_entitlements[ident].append({
            "account_id": ent.account_id,
            "system": ent.system,
            "entitlement": ent.entitlement,
        })

    for ident, ents in identity_entitlements.items():
        for pair_a, pair_b in pairs:
            has_a = [e for e in ents if pair_a in e["entitlement"].lower()]
            has_b = [e for e in ents if pair_b in e["entitlement"].lower()]
            if has_a and has_b:
                is_multi_hop = has_a[0]["account_id"] != has_b[0]["account_id"]
                toxic_findings.append({
                    "identity_id": ident,
                    "finding_type": "multi_hop_sod" if is_multi_hop else "toxic_combination",
                    "severity": "critical" if is_multi_hop else "high",
                    "conflict": f"{pair_a} + {pair_b}",
                    "account_a": has_a[0]["account_id"],
                    "entitlement_a": has_a[0]["entitlement"],
                    "system_a": has_a[0]["system"],
                    "account_b": has_b[0]["account_id"],
                    "entitlement_b": has_b[0]["entitlement"],
                    "system_b": has_b[0]["system"],
                    "description": (
                        f"Identity holds conflicting privileges '{pair_a}' on {has_a[0]['system']} "
                        f"and '{pair_b}' on {has_b[0]['system']}"
                        + (" across multiple distinct accounts (Multi-Hop SoD)." if is_multi_hop else ".")
                    ),
                })

    return toxic_findings


def find_unused_entitlements(
    bundle: CanonicalBundle,
    dormant_days: int = 90,
) -> list[dict[str, Any]]:
    """
    Finds entitlements with last_used > dormant_days or zero observed event activity.
    """
    now = datetime.now(timezone.utc)
    # Collect systems and actions used in events per account
    active_account_systems = set()
    for ev in bundle.events:
        active_account_systems.add((ev.user_key, ev.system))

    unused = []
    for ent in bundle.entitlements:
        days_idle = None
        is_unused = False
        reason = ""

        if ent.last_used:
            try:
                if isinstance(ent.last_used, str):
                    lu = datetime.fromisoformat(ent.last_used.replace("Z", "+00:00"))
                else:
                    lu = ent.last_used if ent.last_used.tzinfo else ent.last_used.replace(tzinfo=timezone.utc)
                days_idle = (now - lu).days
                if days_idle >= dormant_days:
                    is_unused = True
                    reason = f"Last used {days_idle} days ago (exceeds {dormant_days}-day policy)"
            except Exception:
                pass
        else:
            # No last_used recorded; check if account has events in that system
            if (ent.account_id, ent.system) not in active_account_systems:
                is_unused = True
                reason = f"Zero observed event activity in system '{ent.system}'"

        if is_unused:
            unused.append({
                "account_id": ent.account_id,
                "system": ent.system,
                "entitlement": ent.entitlement,
                "privilege_weight": ent.privilege_weight,
                "days_idle": days_idle,
                "reason": reason,
            })

    return unused
