"""
backend/api/remediation.py — FastAPI router for Remediation Proposals, Approvals, and Dry-Run Export.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel

from remediation.plan import RemediationProposal, generate_dryrun_script
from remediation.approvals import (
    create_proposal,
    transition_proposal,
    list_proposals,
    get_audit_log,
    seed_default_proposals_if_empty,
)
from ingest.legacy_adapter import load_legacy_as_canonical
from graph.build import build_identity_graph
from graph.toxic import detect_toxic_combinations, find_unused_entitlements

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])


def ensure_seeded_proposals():
    # If no proposals yet, seed proposals from toxic combinations & unused privileges
    bundle = load_legacy_as_canonical()
    g = build_identity_graph(bundle)
    toxic = detect_toxic_combinations(bundle, g)
    unused = find_unused_entitlements(bundle)

    sample = []
    idx = 101
    for t in toxic[:5]:
        sample.append(RemediationProposal(
            proposal_id=f"PROP-{idx}",
            target_identity=t["identity_id"],
            target_account=t["account_b"],
            target_system=t["system_b"],
            action_type="revoke_entitlement",
            entitlement=t["entitlement_b"],
            reason=f"Multi-Hop SoD Conflict: {t['conflict']}",
            risk_severity=t["severity"],
            impact_classification="safe",
            status="proposed",
        ))
        idx += 1

    for u in unused[:5]:
        sample.append(RemediationProposal(
            proposal_id=f"PROP-{idx}",
            target_identity=u["account_id"],
            target_account=u["account_id"],
            target_system=u["system"],
            action_type="revoke_entitlement",
            entitlement=u["entitlement"],
            reason=u["reason"],
            risk_severity="medium",
            impact_classification="safe",
            status="proposed",
        ))
        idx += 1

    seed_default_proposals_if_empty(sample)


class CreateProposalRequest(BaseModel):
    target_identity: str
    target_account: str
    target_system: str
    action_type: str = "revoke_entitlement"
    entitlement: str | None = None
    reason: str
    risk_severity: str = "high"
    impact_classification: str = "safe"


class TransitionRequest(BaseModel):
    to_status: str  # approved, rejected, exported
    actor: str = "SecOps_Analyst"
    note: str | None = None


@router.get("")
def get_remediation_proposals(status: str | None = Query(None)) -> dict[str, Any]:
    """Lists remediation proposals with optional status filter."""
    ensure_seeded_proposals()
    props = list_proposals(status=status)
    return {
        "status": "success",
        "total_count": len(props),
        "proposals": [p.model_dump() for p in props],
    }


@router.post("")
def add_remediation_proposal(req: CreateProposalRequest) -> dict[str, Any]:
    """Creates a new proposal in the remediation queue."""
    import uuid
    prop_id = f"PROP-{uuid.uuid4().hex[:6].upper()}"
    proposal = RemediationProposal(
        proposal_id=prop_id,
        target_identity=req.target_identity,
        target_account=req.target_account,
        target_system=req.target_system,
        action_type=req.action_type,
        entitlement=req.entitlement,
        reason=req.reason,
        risk_severity=req.risk_severity,
        impact_classification=req.impact_classification,
        status="proposed",
    )
    created = create_proposal(proposal, actor="User_Interactive")
    return {"status": "success", "proposal": created.model_dump()}


@router.post("/{proposal_id}/transition")
def change_proposal_status(proposal_id: str, req: TransitionRequest) -> dict[str, Any]:
    """Transitions proposal status with strict state machine verification."""
    try:
        updated = transition_proposal(
            proposal_id=proposal_id,
            to_status=req.to_status,
            actor=req.actor,
            note=req.note,
        )
        return {"status": "success", "proposal": updated.model_dump()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{proposal_id}/export")
def export_dryrun(
    proposal_id: str,
    format: str = Query("ticket", pattern="^(ticket|csv|aws|entra|okta|ad)$"),
):
    """Exports dry-run remediation artifact in specified format."""
    props = [p for p in list_proposals() if p.proposal_id == proposal_id]
    if not props:
        raise HTTPException(status_code=404, detail=f"Proposal '{proposal_id}' not found.")

    prop = props[0]
    content = generate_dryrun_script(prop, target_format=format)

    media_types = {
        "ticket": "application/json",
        "csv": "text/csv",
        "aws": "text/x-shellscript",
        "entra": "text/plain",
        "okta": "text/plain",
        "ad": "text/plain",
    }
    exts = {
        "ticket": "json",
        "csv": "csv",
        "aws": "sh",
        "entra": "ps1",
        "okta": "sh",
        "ad": "ps1",
    }

    # Automatically mark as exported if approved
    if prop.status == "approved":
        try:
            transition_proposal(prop.proposal_id, "exported", actor="Export_API")
        except ValueError:
            pass

    return Response(
        content=content,
        media_type=media_types.get(format, "text/plain"),
        headers={
            "Content-Disposition": f"attachment; filename=ispad_{prop.proposal_id}_{format}.{exts.get(format, 'txt')}"
        },
    )


@router.get("/audit/log")
def get_remediation_audit_log() -> dict[str, Any]:
    """Returns the complete immutable remediation audit log."""
    return {"status": "success", "audit_log": get_audit_log()}
