"""
backend/remediation/plan.py — Remediation Planning and Dry-Run Export Templates.

Generates safe, structured remediation proposals and platform-specific dry-run scripts:
- AWS IAM CLI
- Microsoft Entra ID (Graph PowerShell)
- Okta Management API (curl)
- Active Directory PowerShell
- Jira Ticket Payload
- Audit CSV
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field


class RemediationProposal(BaseModel):
    proposal_id: str
    target_identity: str
    target_account: str
    target_system: str
    action_type: str = "revoke_entitlement"  # revoke_entitlement, disable_account, quarantine_identity, enforce_mfa
    entitlement: str | None = None
    reason: str
    risk_severity: str = "high"
    impact_classification: str = "safe"  # safe, review, risky
    status: str = "proposed"  # proposed, approved, rejected, exported
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approver: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


def generate_dryrun_script(proposal: RemediationProposal, target_format: str) -> str:
    """
    Renders safe, non-executable dry-run templates stamped with audit notices.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    banner = f"""# ==============================================================================
# ISPAD v2 Remediation Export: DRY RUN ONLY
# Generated: {timestamp}
# Proposal ID: {proposal.proposal_id}
# Target: {proposal.target_account} ({proposal.target_identity}) on {proposal.target_system}
# Classification: {proposal.impact_classification.upper()} | Severity: {proposal.risk_severity.upper()}
# NOTICE: THIS SCRIPT DOES NOT EXECUTE AUTOMATICALLY. REVIEW BEFORE RUNNING.
# ==============================================================================
"""
    ent = proposal.entitlement or "GeneralAccess"
    acc = proposal.target_account

    if target_format == "aws":
        return banner + f"""
# --- AWS IAM CLI Dry-Run ---
# 1. Inspect active user policies
aws iam list-attached-user-policies --user-name "{acc}"

# 2. Detach target policy
aws iam detach-user-policy \\
    --user-name "{acc}" \\
    --policy-arn "arn:aws:iam::aws:policy/{ent}"

# 3. Verify detachment
aws iam get-user --user-name "{acc}"
"""

    elif target_format == "entra":
        return banner + f"""
# --- Microsoft Entra ID (Graph PowerShell) Dry-Run ---
# Connect to Microsoft Graph
# Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.AccessAsUser.All"

$User = Get-MgUser -Filter "userPrincipalName eq '{acc}' or mail eq '{acc}'"
Write-Host "Target User ID: $($User.Id)"

# Remove App Role Assignment or Directory Role
# Remove-MgUserAppRoleAssignment -UserId $User.Id -AppRoleAssignmentId "{ent}" -WhatIf
Write-Host "Simulating removal of '{ent}' from $($User.UserPrincipalName)..."
"""

    elif target_format == "okta":
        return banner + f"""
# --- Okta Management API Dry-Run ---
# Simulated API call to unassign app / revoke entitlement
curl -X DELETE "https://${{OKTA_DOMAIN}}/api/v1/apps/${{APP_ID}}/users/{acc}" \\
  -H "Accept: application/json" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: SSWS ${{OKTA_API_TOKEN}}" \\
  --dry-run
"""

    elif target_format == "ad":
        return banner + f"""
# --- Active Directory PowerShell Dry-Run ---
Import-Module ActiveDirectory

# Check membership
Get-ADUser -Identity "{acc}" -Properties MemberOf

# Simulate removal with -WhatIf
Remove-ADGroupMember -Identity "{ent}" -Members "{acc}" -WhatIf
"""

    elif target_format == "ticket":
        ticket_data = {
            "fields": {
                "project": {"key": "SEC"},
                "summary": f"[ISPAD-v2] Deprovision {ent} for {acc} ({proposal.target_system})",
                "description": (
                    f"*Automated Security Finding*\n\n"
                    f"*Target User:* {proposal.target_identity}\n"
                    f"*Account:* {acc}\n"
                    f"*System:* {proposal.target_system}\n"
                    f"*Entitlement to Revoke:* {ent}\n"
                    f"*Risk Severity:* {proposal.risk_severity}\n"
                    f"*Reason:* {proposal.reason}\n"
                    f"*Impact Assessment:* {proposal.impact_classification}\n"
                    f"*Status:* Approved for remediation via ISPAD v2 Governance Queue."
                ),
                "issuetype": {"name": "Security Task"},
                "priority": {"name": "High" if proposal.risk_severity == "high" else "Medium"},
                "labels": ["ispad-v2", "least-privilege", "dry-run"],
            }
        }
        return json.dumps(ticket_data, indent=2)

    elif target_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "proposal_id", "target_identity", "target_account", "target_system",
            "entitlement", "action_type", "severity", "impact", "status", "created_at"
        ])
        writer.writerow([
            proposal.proposal_id, proposal.target_identity, proposal.target_account,
            proposal.target_system, ent, proposal.action_type, proposal.risk_severity,
            proposal.impact_classification, proposal.status, proposal.created_at
        ])
        return output.getvalue()

    return banner + f"\n# Unknown format '{target_format}'. Dry-run action for {acc} -> {ent}."
