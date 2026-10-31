"""
backend/security/nhi.py — Non-Human Identity (NHI) Governance & Lifecycle Engine.

Tracks, audits, and secures Non-Human Identities (service accounts, API tokens, bots, MCP agents):
- Identifies unowned service accounts (no human custodian assigned).
- Detects overprivileged service accounts holding administrative roles.
- Flags interactive login anomalies on non-human credentials.
- Calculates NHI risk severity.
"""
from __future__ import annotations

import re
from typing import Any
from core.models import CanonicalBundle

NHI_NAME_PATTERN = re.compile(
    r"(?i)(^(svc|bot|batch|sys|app[-_]|daemon|service|api[-_]|pipeline|worker|agent|runner)|[-_]svc$|service$|_service)",
)


def audit_non_human_identities(bundle: CanonicalBundle) -> dict[str, Any]:
    """
    Scans accounts and events for non-human identities, evaluating governance gaps.
    """
    nhi_records = []
    identities_by_emp = {i.employee_id: i for i in bundle.identities if i.employee_id}
    identities_by_email = {i.email.lower(): i for i in bundle.identities if i.email}

    # Track interactive actions per account from events
    interactive_actions = {"interactive_login", "console_login", "ssh_session", "rdp_session"}
    interactive_accounts = set()
    for ev in bundle.events:
        if ev.action.lower() in interactive_actions:
            interactive_accounts.add(ev.user_key)

    total_nhi = 0
    unowned_count = 0
    admin_nhi_count = 0

    for acc in bundle.accounts:
        is_nhi = acc.account_type == "service" or bool(NHI_NAME_PATTERN.search(acc.username))
        if not is_nhi:
            continue

        total_nhi += 1

        # Check custodian
        custodian = None
        if acc.employee_id_hint and acc.employee_id_hint in identities_by_emp:
            custodian = identities_by_emp[acc.employee_id_hint].full_name
        elif acc.email and acc.email.lower() in identities_by_email:
            custodian = identities_by_email[acc.email.lower()].full_name

        has_owner = custodian is not None
        if not has_owner:
            unowned_count += 1

        is_admin = acc.privilege_level == "admin"
        if is_admin:
            admin_nhi_count += 1

        interactive = acc.account_id in interactive_accounts or acc.username in interactive_accounts

        # Risk scoring
        risk_flags = []
        if not has_owner:
            risk_flags.append("NO_HUMAN_CUSTODIAN")
        if is_admin:
            risk_flags.append("OVERPRIVILEGED_ADMIN_NHI")
        if interactive:
            risk_flags.append("ANOMALOUS_INTERACTIVE_USAGE")

        severity = "CRITICAL" if len(risk_flags) >= 2 else "HIGH" if len(risk_flags) == 1 else "LOW"

        nhi_records.append({
            "account_id": acc.account_id,
            "username": acc.username,
            "system": acc.system,
            "has_custodian": has_owner,
            "custodian_name": custodian or "UNASSIGNED",
            "privilege_level": acc.privilege_level,
            "status": acc.status,
            "risk_severity": severity,
            "risk_flags": risk_flags,
            "last_login": acc.last_login.isoformat() if hasattr(acc.last_login, "isoformat") else acc.last_login,
        })

    return {
        "status": "success",
        "total_non_human_identities": total_nhi,
        "unowned_count": unowned_count,
        "overprivileged_count": admin_nhi_count,
        "records": nhi_records,
    }
