"""
tests/test_nhi.py — Unit Tests for Non-Human Identity (NHI) Governance & Auditing.
"""
from __future__ import annotations

from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEvent,
    CanonicalIdentity,
)
from security.nhi import audit_non_human_identities


def test_nhi_governance_detection():
    bundle = CanonicalBundle(
        identities=[
            CanonicalIdentity(
                identity_id="ID_CUSTODIAN",
                employee_id="E100",
                full_name="Sarah Ops",
                employment_status="active",
                source="hr",
            )
        ],
        accounts=[
            # Owned service account
            CanonicalAccount(
                account_id="ACC_SVC_BACKUP",
                system="BACKUP_SYSTEM",
                username="svc_db_backup",
                account_type="service",
                employee_id_hint="E100",
                privilege_level="standard",
                source="iam",
            ),
            # Unowned admin service account
            CanonicalAccount(
                account_id="ACC_SVC_ORPHAN",
                system="AWS_PROD",
                username="deployer_bot",
                account_type="service",
                employee_id_hint=None,
                email=None,
                privilege_level="admin",
                source="aws",
            ),
            # Standard human account
            CanonicalAccount(
                account_id="ACC_HUMAN",
                system="EMAIL",
                username="sarah_ops",
                account_type="human",
                source="okta",
            ),
        ],
        events=[
            # Interactive action on deployer_bot
            CanonicalEvent(
                event_id="EV_BOT_LOGIN",
                timestamp="2026-10-16T12:00:00Z",
                user_key="ACC_SVC_ORPHAN",
                action="console_login",
                system="AWS_PROD",
            )
        ],
    )

    res = audit_non_human_identities(bundle)
    assert res["status"] == "success"
    assert res["total_non_human_identities"] == 2
    assert res["unowned_count"] == 1
    assert res["overprivileged_count"] == 1

    records = {r["account_id"]: r for r in res["records"]}

    # Backup service account: has custodian, standard privilege
    backup_rec = records["ACC_SVC_BACKUP"]
    assert backup_rec["has_custodian"] is True
    assert backup_rec["custodian_name"] == "Sarah Ops"

    # Orphan deployer bot: no custodian, admin privilege, interactive usage -> CRITICAL
    orphan_rec = records["ACC_SVC_ORPHAN"]
    assert orphan_rec["has_custodian"] is False
    assert orphan_rec["risk_severity"] == "CRITICAL"
    assert "NO_HUMAN_CUSTODIAN" in orphan_rec["risk_flags"]
    assert "OVERPRIVILEGED_ADMIN_NHI" in orphan_rec["risk_flags"]
    assert "ANOMALOUS_INTERACTIVE_USAGE" in orphan_rec["risk_flags"]
