"""backend/api/resolution.py
FastAPI router for Feature 1b: Identity Resolution Engine.
"""
from __future__ import annotations

import json
from typing import Any

from core.db import (
    AccountClassificationRecord,
    AccountLinkRecord,
    AuditLogRecord,
    GoldenIdentityRecord,
    ReviewQueueRecord,
    get_session,
)
from fastapi import APIRouter, HTTPException
from ingest.legacy_adapter import load_legacy_bundle
from pydantic import BaseModel, Field
from resolve.engine import (
    manual_merge_identities,
    manual_split_account,
    run_identity_resolution,
)

router = APIRouter(prefix="/api/resolution", tags=["Identity Resolution"])


class RunResolutionPayload(BaseModel):
    run_id: str = "default"
    auto_merge_threshold: float = 0.90
    review_threshold: float = 0.70


class MergePayload(BaseModel):
    target_identity_id: str
    source_identity_id: str
    actor: str = "analyst"


class SplitPayload(BaseModel):
    account_id: str
    actor: str = "analyst"


class ReviewDecisionPayload(BaseModel):
    action: str = Field(..., pattern="^(accept|reject)$")
    actor: str = "analyst"


@router.post("/run")
def trigger_resolution(payload: RunResolutionPayload) -> dict[str, Any]:
    """Trigger identity resolution on a canonical bundle."""
    try:
        # Load canonical bundle (defaults to legacy adapter if no specific run data)
        bundle = load_legacy_bundle(run_id=payload.run_id)
        result = run_identity_resolution(
            bundle=bundle,
            auto_merge_threshold=payload.auto_merge_threshold,
            review_threshold=payload.review_threshold,
            persist=True,
        )
        return {
            "status": "success",
            "run_id": result.run_id,
            "metrics": result.metrics,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Identity resolution failed: {e}") from e


@router.get("/{run_id}")
def get_resolution_summary(run_id: str) -> dict[str, Any]:
    """Retrieve identity resolution metrics and summary counts for a given run."""
    session = get_session()
    try:
        golden_count = session.query(GoldenIdentityRecord).filter(
            GoldenIdentityRecord.run_id == run_id,
        ).count()

        # If no results exist yet for this run_id, run it automatically on legacy bundle
        if golden_count == 0:
            bundle = load_legacy_bundle(run_id=run_id)
            res = run_identity_resolution(bundle, persist=True)
            return {"run_id": run_id, "metrics": res.metrics}

        accounts_count = session.query(AccountLinkRecord).filter(
            AccountLinkRecord.run_id == run_id,
        ).count()

        review_count = session.query(ReviewQueueRecord).filter(
            ReviewQueueRecord.run_id == run_id,
            ReviewQueueRecord.status == "pending",
        ).count()

        class_records = session.query(AccountClassificationRecord).filter(
            AccountClassificationRecord.run_id == run_id,
        ).all()

        counts: dict[str, int] = {}
        for c in class_records:
            counts[c.classification] = counts.get(c.classification, 0) + 1

        metrics = {
            "golden_identities_count": golden_count,
            "account_links_count": accounts_count,
            "review_queue_count": review_count,
            "orphaned_count": counts.get("orphaned", 0),
            "leaver_active_count": counts.get("leaver_active", 0),
            "dormant_count": counts.get("dormant", 0),
            "service_count": counts.get("service", 0),
            "shared_count": counts.get("shared", 0),
            "human_count": counts.get("human", 0),
        }

        return {"run_id": run_id, "metrics": metrics}
    finally:
        session.close()


@router.get("/{run_id}/clusters")
def get_resolution_clusters(run_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve golden identity clusters with linked accounts."""
    session = get_session()
    try:
        goldens = session.query(GoldenIdentityRecord).filter(
            GoldenIdentityRecord.run_id == run_id,
        ).limit(limit).all()

        links = session.query(AccountLinkRecord).filter(
            AccountLinkRecord.run_id == run_id,
        ).all()

        links_by_ident: dict[str, list[dict[str, Any]]] = {}
        for lk in links:
            links_by_ident.setdefault(lk.identity_id, []).append({
                "account_id": lk.account_id,
                "system": lk.system,
                "username": lk.username,
                "confidence": lk.confidence,
                "reasons": json.loads(lk.reasons_json or "[]"),
                "is_manual": bool(lk.is_manual),
                "status": lk.status,
            })

        out = []
        for g in goldens:
            out.append({
                "identity_id": g.identity_id,
                "canonical_name": g.canonical_name,
                "primary_email": g.primary_email,
                "employee_id": g.employee_id,
                "department": g.department,
                "job_title": g.job_title,
                "employment_status": g.employment_status,
                "confidence": g.confidence,
                "sources": json.loads(g.sources_json or "[]"),
                "accounts": links_by_ident.get(g.identity_id, []),
                "cluster_size": len(links_by_ident.get(g.identity_id, [])),
            })
        return out
    finally:
        session.close()


@router.get("/{run_id}/orphans")
def get_orphans(run_id: str) -> list[dict[str, Any]]:
    """Retrieve all accounts classified as orphaned."""
    session = get_session()
    try:
        records = session.query(AccountClassificationRecord).filter(
            AccountClassificationRecord.run_id == run_id,
            AccountClassificationRecord.classification == "orphaned",
        ).all()

        return [
            {
                "account_id": r.account_id,
                "system": r.system,
                "username": r.username,
                "reasons": json.loads(r.reasons_json or "[]"),
                "inactivity_days": r.inactivity_days,
                "risk_level": r.risk_level,
            }
            for r in records
        ]
    finally:
        session.close()


@router.get("/{run_id}/leavers")
def get_leavers(run_id: str) -> list[dict[str, Any]]:
    """Retrieve all accounts classified as leaver_active."""
    session = get_session()
    try:
        records = session.query(AccountClassificationRecord).filter(
            AccountClassificationRecord.run_id == run_id,
            AccountClassificationRecord.classification == "leaver_active",
        ).all()

        return [
            {
                "account_id": r.account_id,
                "system": r.system,
                "username": r.username,
                "owner": r.owner,
                "reasons": json.loads(r.reasons_json or "[]"),
                "inactivity_days": r.inactivity_days,
                "risk_level": r.risk_level,
            }
            for r in records
        ]
    finally:
        session.close()


@router.get("/{run_id}/classifications")
def get_all_classifications(run_id: str, classification_type: str | None = None) -> list[dict[str, Any]]:
    """Retrieve account classifications with optional type filter."""
    session = get_session()
    try:
        q = session.query(AccountClassificationRecord).filter(
            AccountClassificationRecord.run_id == run_id,
        )
        if classification_type:
            q = q.filter(AccountClassificationRecord.classification == classification_type)

        records = q.all()
        return [
            {
                "account_id": r.account_id,
                "system": r.system,
                "username": r.username,
                "classification": r.classification,
                "owner": r.owner,
                "reasons": json.loads(r.reasons_json or "[]"),
                "inactivity_days": r.inactivity_days,
                "risk_level": r.risk_level,
            }
            for r in records
        ]
    finally:
        session.close()


@router.get("/{run_id}/review")
def get_review_queue(run_id: str) -> list[dict[str, Any]]:
    """Retrieve items awaiting manual match adjudication."""
    session = get_session()
    try:
        records = session.query(ReviewQueueRecord).filter(
            ReviewQueueRecord.run_id == run_id,
            ReviewQueueRecord.status == "pending",
        ).all()

        return [
            {
                "item_id": r.item_id,
                "account_id": r.account_id,
                "suggested_identity_id": r.suggested_identity_id,
                "confidence": r.confidence,
                "reasons": json.loads(r.reasons_json or "[]"),
                "account_details": json.loads(r.account_details_json or "{}"),
                "identity_details": json.loads(r.identity_details_json or "{}"),
                "status": r.status,
            }
            for r in records
        ]
    finally:
        session.close()


@router.post("/{run_id}/review/{item_id}/decide")
def decide_review_item(run_id: str, item_id: str, payload: ReviewDecisionPayload) -> dict[str, Any]:
    """Accept or reject a match candidate from the review queue."""
    session = get_session()
    try:
        item = session.query(ReviewQueueRecord).filter(
            ReviewQueueRecord.run_id == run_id,
            ReviewQueueRecord.item_id == item_id,
        ).first()

        if not item:
            raise HTTPException(status_code=404, detail="Review item not found")

        item.status = payload.action

        if payload.action == "accept":
            # Link account to suggested identity
            existing_link = session.query(AccountLinkRecord).filter(
                AccountLinkRecord.run_id == run_id,
                AccountLinkRecord.account_id == item.account_id,
            ).first()

            if existing_link:
                existing_link.identity_id = item.suggested_identity_id
                existing_link.confidence = item.confidence
                existing_link.is_manual = 1
                existing_link.status = "linked"
            else:
                session.add(
                    AccountLinkRecord(
                        run_id=run_id,
                        account_id=item.account_id,
                        identity_id=item.suggested_identity_id,
                        system="system",
                        username=item.account_id,
                        confidence=item.confidence,
                        reasons_json=json.dumps(["Manual review approved"]),
                        is_manual=1,
                        status="linked",
                    )
                )

            # Update golden identity accounts
            golden = session.query(GoldenIdentityRecord).filter(
                GoldenIdentityRecord.run_id == run_id,
                GoldenIdentityRecord.identity_id == item.suggested_identity_id,
            ).first()

            if golden:
                accs = json.loads(golden.linked_account_ids_json or "[]")
                if item.account_id not in accs:
                    accs.append(item.account_id)
                    golden.linked_account_ids_json = json.dumps(accs)

        session.add(
            AuditLogRecord(
                action="REVIEW_QUEUE_DECISION",
                actor=payload.actor,
                entity_type="review_item",
                entity_id=item_id,
                details_json=json.dumps({
                    "decision": payload.action,
                    "account_id": item.account_id,
                    "identity_id": item.suggested_identity_id,
                }),
            )
        )
        session.commit()
        return {"status": "success", "item_id": item_id, "decision": payload.action}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e)) from e
    finally:
        session.close()


@router.post("/{run_id}/merge")
def merge_identities(run_id: str, payload: MergePayload) -> dict[str, Any]:
    """Manually merge two golden identities."""
    try:
        success = manual_merge_identities(
            run_id=run_id,
            target_identity_id=payload.target_identity_id,
            source_identity_id=payload.source_identity_id,
            actor=payload.actor,
        )
        if not success:
            raise HTTPException(status_code=404, detail="One or both identities not found")
        return {"status": "success", "merged_into": payload.target_identity_id}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve)) from ve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/{run_id}/split")
def split_account(run_id: str, payload: SplitPayload) -> dict[str, Any]:
    """Manually detach an account into a new identity."""
    try:
        new_identity_id = manual_split_account(
            run_id=run_id,
            account_id=payload.account_id,
            actor=payload.actor,
        )
        if not new_identity_id:
            raise HTTPException(status_code=404, detail="Account link not found")
        return {"status": "success", "new_identity_id": new_identity_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
