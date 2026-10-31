"""backend/detect/heuristics.py
Configurable Separation of Duties (SoD) and Security Heuristics for Kavach v2.

Evaluates:
- YAML-configurable SoD conflicts across entitlements and actions.
- Stale privileged accounts (NIST AC-2 compliance).
- Privilege creep (outliers above peer 90th percentile).
- High-sensitivity data export during unusual hours.
- Service account interactive admin operations.
- LLM suggestion helper for proposed SoD rules.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from config import get_settings
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEvent,
)
from detect.features import parse_iso_dt


class SoDRule:

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        entitlement_conflicts: list[list[str]],
        action_conflicts: list[list[str]],
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.entitlement_conflicts = entitlement_conflicts
        self.action_conflicts = action_conflicts


def load_sod_rules(yaml_path: str | Path | None = None) -> list[SoDRule]:
    """Load configurable SoD rules from YAML file."""
    cfg = get_settings()
    path = Path(yaml_path or getattr(cfg, "SOD_CONFIG_PATH", "config/sod.yaml"))

    if not path.exists():
        # Look in workspace root
        root_path = Path(__file__).resolve().parent.parent.parent / "config" / "sod.yaml"
        if root_path.exists():
            path = root_path

    if not path.exists():
        return []

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw_rules = data.get("rules", [])
        rules: list[SoDRule] = []
        for r in raw_rules:
            rules.append(
                SoDRule(
                    rule_id=r.get("id", "SOD_UNKNOWN"),
                    name=r.get("name", "SoD Rule"),
                    description=r.get("description", ""),
                    severity=r.get("severity", "high"),
                    entitlement_conflicts=r.get("entitlement_conflicts", []),
                    action_conflicts=r.get("action_conflicts", []),
                )
            )
        return rules
    except Exception as e:
        print(f"Warning: Failed to load SoD rules from {path}: {e}")
        return []


def evaluate_heuristics(
    bundle: CanonicalBundle,
    user_peer_map: dict[str, str] | None = None,
    sod_rules: list[SoDRule] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Evaluate deterministic security heuristics across all users in bundle.

    Returns dict mapping user_id -> list of finding dicts:
    {
        "id": str,
        "type": str,
        "name": str,
        "severity": "low" | "medium" | "high" | "critical",
        "description": str,
        "hard_rule": bool,
        "score_weight": float,
    }
    """
    cfg = get_settings()
    stale_threshold = getattr(cfg, "STALE_DAYS_THRESHOLD", 30)

    if sod_rules is None:
        sod_rules = load_sod_rules()

    identities = bundle.identities
    accounts = bundle.accounts
    events = bundle.events
    entitlements = bundle.entitlements

    # Compute reference timestamp across dataset for time-bounded compliance rules
    reference_time: datetime | None = None
    for e in events:
        dt = parse_iso_dt(e.timestamp)
        if dt and (reference_time is None or dt > reference_time):
            reference_time = dt
    for a in accounts:
        dt = parse_iso_dt(a.last_login)
        if dt and (reference_time is None or dt > reference_time):
            reference_time = dt
    if reference_time is None:
        reference_time = datetime.now()

    # Index users, accounts, events, entitlements
    all_users = set()
    user_accounts: dict[str, list[CanonicalAccount]] = defaultdict(list)
    user_events: dict[str, list[CanonicalEvent]] = defaultdict(list)
    user_entitlements: dict[str, set[str]] = defaultdict(set)

    for i in identities:
        all_users.add(i.identity_id)

    for a in accounts:
        uid = a.extra.get("identity_id") or a.username or a.account_id
        all_users.add(uid)
        user_accounts[uid].append(a)

    for e in events:
        all_users.add(e.user_key)
        user_events[e.user_key].append(e)

    for ent in entitlements:
        # map to account
        target_u = ent.account_id
        user_entitlements[target_u].add(ent.entitlement.lower())

    # Map user account entitlements to primary user
    for uid, accs in user_accounts.items():
        for a in accs:
            if a.account_id in user_entitlements:
                user_entitlements[uid].update(user_entitlements[a.account_id])
            if a.username in user_entitlements:
                user_entitlements[uid].update(user_entitlements[a.username])

    # Precalculate peer entitlement distributions for privilege creep
    peer_ent_counts: dict[str, list[int]] = defaultdict(list)
    for uid in all_users:
        gid = (user_peer_map or {}).get(uid, "general")
        cnt = len(user_entitlements.get(uid, set()))
        peer_ent_counts[gid].append(cnt)

    peer_p90: dict[str, float] = {}
    for gid, counts in peer_ent_counts.items():
        if len(counts) >= 5:
            peer_p90[gid] = float(np.percentile(counts, 90))
        else:
            peer_p90[gid] = 999.0

    findings_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)

    terminated_on = {
        i.identity_id: dt
        for i in identities
        if str(i.employment_status).lower() == "terminated" and (dt := parse_iso_dt(i.termination_date))
    }

    for uid in all_users:
        u_accs = user_accounts.get(uid, [])
        u_evs = user_events.get(uid, [])
        u_ents = user_entitlements.get(uid, set())
        u_actions = {e.action.lower() for e in u_evs if e.action}

        # ── 1. Separation of Duties (SoD) Violations ──────────────────────────
        for rule in sod_rules:
            # Check entitlement conflicts
            for pair in rule.entitlement_conflicts:
                if len(pair) == 2:
                    p1, p2 = pair[0].lower(), pair[1].lower()
                    if p1 in u_ents and p2 in u_ents:
                        findings_by_user[uid].append({
                            "id": f"{rule.rule_id}_ENT",
                            "type": "sod_conflict",
                            "name": f"SoD: {rule.name}",
                            "severity": rule.severity,
                            "description": f"User holds conflicting entitlements ('{p1}' and '{p2}'): {rule.description}",
                            "hard_rule": True,
                            "score_weight": 25.0,
                        })
                        break

            # Check action execution conflicts
            for pair in rule.action_conflicts:
                if len(pair) == 2:
                    a1, a2 = pair[0].lower(), pair[1].lower()
                    if a1 in u_actions and a2 in u_actions:
                        findings_by_user[uid].append({
                            "id": f"{rule.rule_id}_ACT",
                            "type": "sod_conflict",
                            "name": f"SoD Action Execution: {rule.name}",
                            "severity": rule.severity,
                            "description": f"User executed conflicting actions ('{a1}' and '{a2}')",
                            "hard_rule": True,
                            "score_weight": 30.0,
                        })
                        break

        # ── 2. Stale Privileged Account ───────────────────────────────────────
        for acc in u_accs:
            priv = str(acc.privilege_level).lower()
            if priv in ("admin", "elevated", "power-user"):
                days_inact = 0
                if acc.last_login:
                    dt = parse_iso_dt(acc.last_login)
                    if dt and reference_time:
                        days_inact = max(0, int((reference_time - dt).total_seconds() / 86400.0))
                if days_inact > stale_threshold:
                    findings_by_user[uid].append({
                        "id": f"STALE_PRIV_{acc.account_id}",
                        "type": "stale_privileged",
                        "name": "Stale Privileged Account",
                        "severity": "high",
                        "description": f"Privileged account '{acc.username}' ({acc.system}) inactive for {days_inact} days (NIST AC-2 violation)",
                        "hard_rule": True,
                        "score_weight": 20.0,
                    })
                    break

        # ── 2b. Leaver Still Active (HR says terminated, activity continues) ──
        term = terminated_on.get(uid)
        if term:
            post_term = [e for e in u_evs if (dt := parse_iso_dt(e.timestamp)) and dt > term]
            if post_term:
                findings_by_user[uid].append({
                    "id": "LEAVER_ACTIVE",
                    "type": "leaver_active",
                    "name": "Leaver Still Active",
                    "severity": "critical",
                    "description": (
                        f"HR terminated this employee on {term.date()} but the account is still live "
                        f"and made {len(post_term)} access events afterwards"
                    ),
                    "hard_rule": True,
                    "score_weight": 30.0,
                })

        # ── 3. Privilege Creep (Outlier vs Peers) ─────────────────────────────
        gid = (user_peer_map or {}).get(uid, "general")
        ent_count = len(u_ents)
        p90 = peer_p90.get(gid, 999.0)
        if ent_count > p90 and ent_count >= 8:
            findings_by_user[uid].append({
                "id": "PRIVILEGE_CREEP",
                "type": "privilege_creep",
                "name": "Privilege Creep Outlier",
                "severity": "medium",
                "description": f"User holds {ent_count} entitlements, exceeding 90th percentile ({int(p90)}) of peer group '{gid}'",
                "hard_rule": False,
                "score_weight": 15.0,
            })

        # ── 4. High Sensitivity Export / Operation at Night ───────────────────
        night_admin_or_export = any(
            (e.action in ("export_data", "admin_operation", "modify_security_group"))
            and str(e.resource_sensitivity).lower() in ("high", "crown")
            and ((dt := parse_iso_dt(e.timestamp)) and (dt.hour < 8 or dt.hour >= 18))
            for e in u_evs
        )
        if night_admin_or_export:
            findings_by_user[uid].append({
                "id": "HIGH_SENS_EXPORT_NIGHT",
                "type": "sensitive_access",
                "name": "Off-Hours Sensitive Access / Operation",
                "severity": "high",
                "description": "User executed privileged operation or data export on sensitive assets outside business hours",
                "hard_rule": False,
                "score_weight": 25.0,
            })

        # ── 5. Service Account Interactive Admin Operation ───────────────────
        is_service = any(
            a.account_type == "service"
            or str(a.privilege_level).lower() == "service-account"
            for a in u_accs
        )
        has_admin_op = any(e.action in ("admin_operation", "sudo", "modify_security_group") for e in u_evs)
        if is_service and has_admin_op:
            findings_by_user[uid].append({
                "id": "SERVICE_ACCOUNT_ADMIN_OP",
                "type": "service_abuse",
                "name": "Service Account Interactive Admin Operation",
                "severity": "high",
                "description": "Automated service account performed interactive administrative operations",
                "hard_rule": True,
                "score_weight": 25.0,
            })

        # ── 6. Dominant After Hours Activity ──────────────────────────────────
        if u_evs and len(u_evs) >= 3 and not is_service:
            after_count = sum(
                1 for e in u_evs
                if (dt := parse_iso_dt(e.timestamp)) and (dt.hour < 8 or dt.hour >= 18)
            )
            after_ratio = after_count / len(u_evs)
            if after_ratio > 0.70:
                findings_by_user[uid].append({
                    "id": "DOMINANT_AFTER_HOURS",
                    "type": "behavioral_anomaly",
                    "name": "Dominant After-Hours Activity",
                    "severity": "medium",
                    "description": f"{int(after_ratio * 100)}% of user events occurred outside business hours",
                    "hard_rule": False,
                    "score_weight": 20.0,
                })

        # ── 7. High Failure Rate ──────────────────────────────────────────────
        if u_evs and len(u_evs) >= 3:
            fail_count = sum(1 for e in u_evs if not e.success)
            fail_ratio = fail_count / len(u_evs)
            if fail_ratio > 0.40:
                findings_by_user[uid].append({
                    "id": "HIGH_FAIL_RATIO",
                    "type": "behavioral_anomaly",
                    "name": "High Failure Rate",
                    "severity": "medium",
                    "description": f"{int(fail_ratio * 100)}% of user events failed (possible credential attack or brute-force)",
                    "hard_rule": False,
                    "score_weight": 15.0,
                })

    return dict(findings_by_user)
