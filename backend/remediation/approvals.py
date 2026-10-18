"""
backend/remediation/approvals.py — Remediation State Machine and Immutable Audit Log.

Enforces transition rules:
  proposed -> approved | rejected
  approved -> exported
  rejected -> proposed (re-evaluation)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from remediation.plan import RemediationProposal

# In-memory storage for active run
_PROPOSALS: dict[str, RemediationProposal] = {}
_AUDIT_LOG: list[dict[str, Any]] = []

VALID_TRANSITIONS = {
    "proposed": ["approved", "rejected"],
    "approved": ["exported", "rejected"],
    "rejected": ["proposed"],
    "exported": [],  # Terminal state
}


def create_proposal(proposal: RemediationProposal, actor: str = "Kavach_Engine") -> RemediationProposal:
    """Registers a new remediation proposal in the queue and records an audit log entry."""
    _PROPOSALS[proposal.proposal_id] = proposal
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": "PROPOSAL_CREATED",
        "proposal_id": proposal.proposal_id,
        "target_account": proposal.target_account,
        "from_status": None,
        "to_status": proposal.status,
    }
    _AUDIT_LOG.append(log_entry)
    proposal.history.append(log_entry)
    return proposal


def transition_proposal(
    proposal_id: str,
    to_status: str,
    actor: str = "SecOps_Analyst",
    note: str | None = None,
) -> RemediationProposal:
    """Transitions proposal status with strict state machine validation and audit recording."""
    if proposal_id not in _PROPOSALS:
        raise ValueError(f"Remediation proposal '{proposal_id}' not found.")

    prop = _PROPOSALS[proposal_id]
    current = prop.status

    allowed = VALID_TRANSITIONS.get(current, [])
    if to_status not in allowed:
        raise ValueError(
            f"Invalid state transition: cannot transition from '{current}' to '{to_status}'. "
            f"Allowed next states: {allowed}"
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    prop.status = to_status
    prop.updated_at = now_iso
    if to_status == "approved":
        prop.approver = actor

    log_entry = {
        "timestamp": now_iso,
        "actor": actor,
        "action": f"STATUS_CHANGED_{to_status.upper()}",
        "proposal_id": proposal_id,
        "target_account": prop.target_account,
        "from_status": current,
        "to_status": to_status,
        "note": note,
    }
    _AUDIT_LOG.append(log_entry)
    prop.history.append(log_entry)
    return prop


def list_proposals(status: str | None = None) -> list[RemediationProposal]:
    """Lists proposals, optionally filtered by status."""
    props = list(_PROPOSALS.values())
    if status:
        props = [p for p in props if p.status == status]
    return props


def get_audit_log() -> list[dict[str, Any]]:
    """Returns copy of the complete immutable audit log."""
    return list(_AUDIT_LOG)


def seed_default_proposals_if_empty(sample_proposals: list[RemediationProposal]) -> None:
    """Seeds proposals if queue is currently empty."""
    if not _PROPOSALS:
        for p in sample_proposals:
            create_proposal(p, actor="Kavach_Detection_Engine")
