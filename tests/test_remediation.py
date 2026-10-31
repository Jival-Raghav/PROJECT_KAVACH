"""
tests/test_remediation.py — Unit Tests for Remediation State Machine and Dry-Run Export.
"""
from __future__ import annotations

import pytest
from remediation.plan import RemediationProposal, generate_dryrun_script
from remediation.approvals import (
    create_proposal,
    transition_proposal,
)


def test_remediation_lifecycle_and_state_machine():
    prop = RemediationProposal(
        proposal_id="PROP-TEST-001",
        target_identity="USR999",
        target_account="ACC999",
        target_system="AWS_PROD",
        action_type="revoke_entitlement",
        entitlement="IAMFullAccess",
        reason="Test SoD violation",
        risk_severity="critical",
        impact_classification="safe",
        status="proposed",
    )

    created = create_proposal(prop, actor="Tester")
    assert created.status == "proposed"
    assert created.proposal_id == "PROP-TEST-001"

    # Transition to approved
    approved = transition_proposal("PROP-TEST-001", "approved", actor="SecurityLead")
    assert approved.status == "approved"
    assert approved.approver == "SecurityLead"

    # Transition to exported
    exported = transition_proposal("PROP-TEST-001", "exported", actor="Automation")
    assert exported.status == "exported"

    # Attempt invalid transition from exported (terminal state)
    with pytest.raises(ValueError, match="Invalid state transition"):
        transition_proposal("PROP-TEST-001", "proposed")


def test_dryrun_script_generation_formats():
    prop = RemediationProposal(
        proposal_id="PROP-TEST-002",
        target_identity="USR888",
        target_account="ACC888",
        target_system="AWS_PROD",
        action_type="revoke_entitlement",
        entitlement="AdministratorAccess",
        reason="Dormant admin access",
        risk_severity="high",
        impact_classification="safe",
        status="proposed",
    )

    # 1. AWS
    aws_script = generate_dryrun_script(prop, "aws")
    assert "DRY RUN ONLY" in aws_script
    assert "aws iam detach-user-policy" in aws_script
    assert "AdministratorAccess" in aws_script

    # 2. Entra
    entra_script = generate_dryrun_script(prop, "entra")
    assert "Microsoft Entra ID" in entra_script
    assert "Remove-MgUserAppRoleAssignment" in entra_script

    # 3. Okta
    okta_script = generate_dryrun_script(prop, "okta")
    assert "Okta Management API" in okta_script
    assert "--dry-run" in okta_script

    # 4. AD
    ad_script = generate_dryrun_script(prop, "ad")
    assert "Active Directory" in ad_script
    assert "Remove-ADGroupMember" in ad_script

    # 5. Ticket JSON
    ticket_json = generate_dryrun_script(prop, "ticket")
    assert "ISPAD-v2" in ticket_json
    assert "Security Task" in ticket_json

    # 6. CSV
    csv_str = generate_dryrun_script(prop, "csv")
    assert "proposal_id,target_identity" in csv_str
    assert "PROP-TEST-002" in csv_str
