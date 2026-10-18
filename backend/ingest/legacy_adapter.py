"""
ingest/legacy_adapter.py — Adapter seam bridging legacy CSV datasets to CanonicalBundle.
Enforces the seam: raw CSV column names exist ONLY inside this module and ingest readers.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from config import get_settings
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEntitlement,
    CanonicalEvent,
    CanonicalIdentity,
    CanonicalSystem,
)


def _parse_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("1", "true", "yes", "y", "active")


def load_canonical(
    run_id: str = "legacy",
    users_csv_path: Path | str | None = None,
    events_csv_path: Path | str | None = None,
) -> CanonicalBundle:
    """Reads legacy CSVs and converts them into a standardized CanonicalBundle."""
    cfg = get_settings()
    data_dir = Path(cfg.DATA_DIR)

    u_path = Path(users_csv_path) if users_csv_path else data_dir / "identity_users.csv"
    e_path = Path(events_csv_path) if events_csv_path else data_dir / "identity_events.csv"

    identities: list[CanonicalIdentity] = []
    accounts: list[CanonicalAccount] = []
    entitlements: list[CanonicalEntitlement] = []
    events: list[CanonicalEvent] = []
    seen_systems: dict[str, str] = {}

    # 1. Load users
    if u_path.exists():
        with open(u_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row.get("user_id", "").strip()
                username = row.get("username", "").strip()
                email = row.get("email", "").strip()
                dept = row.get("department", "").strip()
                title = row.get("job_title", "").strip()
                priv = row.get("privilege_level", "user").strip()
                raw_systems = row.get("systems_access", "")
                last_login = row.get("last_login", "").strip()
                days_inactive = int(row.get("days_inactive", 0) or 0)
                is_active = _parse_bool(row.get("is_active", True))
                hire_date = row.get("hire_date", "").strip()

                # Parse pipe-separated systems
                sys_list = [s.strip() for s in raw_systems.split("|") if s.strip()] if isinstance(raw_systems, str) else []

                # Create Identity
                identities.append(
                    CanonicalIdentity(
                        identity_id=uid,
                        employee_id=uid,
                        full_name=username,
                        email=email,
                        department=dept,
                        job_title=title,
                        employment_status="active" if is_active else "terminated",
                        hire_date=hire_date,
                        source="legacy_csv",
                        extra={
                            "days_inactive": days_inactive,
                            "is_active": is_active,
                            "systems_access": sys_list,
                            "legacy_privilege_level": priv,
                        },
                    )
                )

                # Create Account
                account_id = f"acc_{uid}"
                accounts.append(
                    CanonicalAccount(
                        account_id=account_id,
                        system="enterprise_directory",
                        username=username,
                        email=email,
                        employee_id_hint=uid,
                        account_type="admin" if priv == "admin" else "human",
                        status="active" if is_active else "disabled",
                        last_login=last_login,
                        privilege_level=priv,
                        source="legacy_csv",
                        extra={
                            "identity_id": uid,
                            "days_inactive": days_inactive,
                            "is_active": is_active,
                            "systems_access": sys_list,
                        },
                    )
                )

                # Create Entitlements per system
                for s in sys_list:
                    entitlements.append(
                        CanonicalEntitlement(
                            account_id=account_id,
                            system=s,
                            entitlement=f"access:{s}",
                            privilege_weight=3.0 if priv == "admin" else 1.0,
                            extra={"identity_id": uid},
                        )
                    )
                    if s not in seen_systems:
                        seen_systems[s] = "high" if s in {"PROD_DB", "SIEM", "Admin_Console", "AWS_IAM"} else "medium"

    # 2. Load events
    if e_path.exists():
        with open(e_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                eid = f"ev_{idx:06d}"
                ts = row.get("timestamp", "").strip()
                uid = row.get("user_id", "").strip()
                action = row.get("action", "").strip()
                res = row.get("resource", "").strip()
                sens = row.get("resource_sensitivity", "low").strip().lower()
                status_raw = row.get("status", "success").strip().lower()
                ip = row.get("source_ip", "").strip()
                tc = row.get("time_classification", "").strip()
                anomaly_marker = row.get("anomaly_marker", "")

                label = None
                if anomaly_marker != "":
                    label = _parse_bool(anomaly_marker)

                events.append(
                    CanonicalEvent(
                        event_id=eid,
                        timestamp=ts,
                        user_key=uid,
                        action=action,
                        resource=res,
                        system=res,  # in legacy format, resource acts as system name
                        resource_sensitivity=sens,
                        success=(status_raw == "success"),
                        source_ip=ip,
                        label=label,
                        raw=dict(row),
                        extra={
                            "time_classification": tc,
                            "status": status_raw,
                            "username": row.get("username", ""),
                        },
                    )
                )
                if res and res not in seen_systems:
                    seen_systems[res] = sens

    systems = [
        CanonicalSystem(system=s_name, sensitivity=s_sens)
        for s_name, s_sens in seen_systems.items()
    ]

    # Load OrgContext if available
    from core.models import OrgContext
    org_ctx = OrgContext()
    candidate_org_dirs = [
        Path("data/synthetic/org_context"),
        Path(__file__).resolve().parent.parent.parent / "data" / "synthetic" / "org_context",
    ]
    for od in candidate_org_dirs:
        if od.exists():
            for name in ("oncall", "tickets", "projects", "leave", "hr_events", "exceptions"):
                p = od / f"{name}.csv"
                if p.exists():
                    with open(p, newline="", encoding="utf-8") as f:
                        setattr(org_ctx, name, list(csv.DictReader(f)))
            break

    return CanonicalBundle(
        run_id=run_id,
        identities=identities,
        accounts=accounts,
        entitlements=entitlements,
        events=events,
        systems=systems,
        org_context=org_ctx,
    )


load_legacy_bundle = load_canonical


def canonical_to_legacy_dicts(
    bundle: CanonicalBundle,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Converts a CanonicalBundle into the exact legacy dictionary representation
    required by legacy pipelines and regression tests.
    """
    raw_users: list[dict[str, Any]] = []
    for ident in bundle.identities:
        # Match accounts
        matching_accs = [
            a for a in bundle.accounts
            if a.extra.get("identity_id") == ident.identity_id
            or a.account_id == f"acc_{ident.identity_id}"
        ]
        acc = matching_accs[0] if matching_accs else None

        # Reconstruct systems_access
        acc_entitlements = [
            e.system for e in bundle.entitlements
            if acc and e.account_id == acc.account_id
        ]
        sys_list = ident.extra.get("systems_access") or acc_entitlements

        raw_users.append({
            "user_id": ident.identity_id,
            "username": ident.full_name or "",
            "email": ident.email or "",
            "department": ident.department or "",
            "job_title": ident.job_title or "",
            "privilege_level": acc.privilege_level if acc else ident.extra.get("legacy_privilege_level", "user"),
            "systems_access": sys_list,
            "last_login": acc.last_login if acc else "",
            "days_inactive": int(ident.extra.get("days_inactive", 0)),
            "is_active": ident.employment_status == "active",
            "hire_date": ident.hire_date or "",
        })

    raw_events: list[dict[str, Any]] = []
    for ev in bundle.events:
        raw_events.append({
            "timestamp": ev.timestamp,
            "user_id": ev.user_key,
            "username": ev.extra.get("username", ""),
            "action": ev.action,
            "resource": ev.resource or "",
            "resource_sensitivity": ev.resource_sensitivity or "low",
            "status": ev.extra.get("status", "success" if ev.success else "failure"),
            "source_ip": ev.source_ip or "",
            "time_classification": ev.extra.get("time_classification", ""),
            "anomaly_marker": str(ev.label) if ev.label is not None else "",
        })

    return raw_users, raw_events


# Backward compatibility alias
load_legacy_as_canonical = load_canonical
