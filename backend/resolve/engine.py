"""backend/resolve/engine.py
Identity Resolution Pipeline Orchestrator for ISPAD v2.

Integrates:
- Normalization (NFKD, nickname alias dictionary, email/username local-part)
- Multi-key blocking (employee_id, surname, email prefix, initials+surname)
- Deterministic & fuzzy weighted pair matching
- Constrained Union-Find (never merges conflicting non-null employee IDs)
- Account risk classification (orphans, leaver-active, dormant, service, shared)
- Golden identity graph synthesis & persistence
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
from core.models import (
    CanonicalBundle,
    ResolutionResult,
)
from resolve.blocking import generate_candidate_pairs
from resolve.classify import classify_accounts
from resolve.cluster import build_golden_clusters
from resolve.match import compute_pair_score


def run_identity_resolution(
    bundle: CanonicalBundle,
    auto_merge_threshold: float = 0.90,
    review_threshold: float = 0.70,
    persist: bool = True,
) -> ResolutionResult:
    """Execute complete identity resolution and account classification on a CanonicalBundle."""
    run_id = bundle.run_id or "default"
    identities = bundle.identities
    accounts = bundle.accounts
    events = bundle.events

    # 1. Prepare record dictionaries for blocking and matching
    records: list[dict[str, Any]] = []

    # Map HR identities
    for ident in identities:
        records.append({
            "_record_id": f"id:{ident.identity_id}",
            "_type": "identity",
            "identity_id": ident.identity_id,
            "employee_id": ident.employee_id,
            "full_name": ident.full_name,
            "name": ident.full_name,
            "email": ident.email,
            "department": ident.department,
            "job_title": ident.job_title,
            "employment_status": ident.employment_status,
        })

    # Map Accounts
    for acc in accounts:
        records.append({
            "_record_id": f"acc:{acc.account_id}",
            "_type": "account",
            "account_id": acc.account_id,
            "system": acc.system,
            "username": acc.username,
            "user_key": acc.username,
            "email": acc.email,
            "employee_id": acc.employee_id_hint,
            "employee_id_hint": acc.employee_id_hint,
            "account_type": acc.account_type,
            "privilege_level": acc.privilege_level,
            "department": acc.extra.get("department"),
        })

    record_map = {r["_record_id"]: r for r in records}

    # 2. Multi-Key Blocking
    candidate_pairs = generate_candidate_pairs(records)

    # 3. Pair Scoring
    scored_pairs: list[dict[str, Any]] = []
    for id_a, id_b in candidate_pairs:
        rec_a = record_map.get(id_a)
        rec_b = record_map.get(id_b)
        if not rec_a or not rec_b:
            continue

        score, reasons = compute_pair_score(rec_a, rec_b)
        if score >= review_threshold:
            scored_pairs.append({
                "id_a": id_a,
                "id_b": id_b,
                "score": score,
                "reasons": reasons,
                "rec_a": rec_a,
                "rec_b": rec_b,
            })

    # 4. Constrained Clustering & Golden Identity Synthesis
    golden_identities, account_links, review_queue, refused_merges = build_golden_clusters(
        identities=identities,
        accounts=accounts,
        scored_pairs=scored_pairs,
        auto_merge_threshold=auto_merge_threshold,
        review_threshold=review_threshold,
    )

    # 5. Account Risk Classification
    classifications = classify_accounts(
        accounts=accounts,
        identities=identities,
        golden_identities=golden_identities,
        events=events,
    )

    # 6. Aggregate Summary Metrics
    class_counts: dict[str, int] = {}
    for cl in classifications:
        class_counts[cl.classification] = class_counts.get(cl.classification, 0) + 1

    metrics: dict[str, Any] = {
        "total_accounts": len(accounts),
        "total_hr_identities": len(identities),
        "golden_identities_count": len(golden_identities),
        "account_links_count": len(account_links),
        "candidate_pairs_evaluated": len(candidate_pairs),
        "review_queue_count": len(review_queue),
        "refused_merges_count": len(refused_merges),
        "orphaned_count": class_counts.get("orphaned", 0),
        "leaver_active_count": class_counts.get("leaver_active", 0),
        "dormant_count": class_counts.get("dormant", 0),
        "service_count": class_counts.get("service", 0),
        "shared_count": class_counts.get("shared", 0),
        "human_count": class_counts.get("human", 0),
    }

    result = ResolutionResult(
        run_id=run_id,
        golden_identities=golden_identities,
        account_links=account_links,
        review_queue=review_queue,
        classifications=classifications,
        metrics=metrics,
    )

    # 7. Persist to SQLite Database
    if persist:
        _persist_resolution_result(result, refused_merges)

    return result


def _persist_resolution_result(
    result: ResolutionResult,
    refused_merges: list[dict[str, Any]],
) -> None:
    session = get_session()
    try:
        run_id = result.run_id

        # Clear existing records for this run to maintain idempotency
        session.query(GoldenIdentityRecord).filter(GoldenIdentityRecord.run_id == run_id).delete()
        session.query(AccountLinkRecord).filter(AccountLinkRecord.run_id == run_id).delete()
        session.query(ReviewQueueRecord).filter(ReviewQueueRecord.run_id == run_id).delete()
        session.query(AccountClassificationRecord).filter(AccountClassificationRecord.run_id == run_id).delete()

        # Insert Golden Identities
        for gid in result.golden_identities:
            session.add(
                GoldenIdentityRecord(
                    identity_id=gid.identity_id,
                    run_id=run_id,
                    canonical_name=gid.canonical_name,
                    primary_email=gid.primary_email,
                    employee_id=gid.employee_id,
                    department=gid.department,
                    job_title=gid.job_title,
                    employment_status=gid.employment_status,
                    linked_account_ids_json=json.dumps(gid.linked_account_ids),
                    confidence=gid.confidence,
                    sources_json=json.dumps(gid.sources),
                )
            )

        # Insert Account Links
        for link in result.account_links:
            session.add(
                AccountLinkRecord(
                    run_id=run_id,
                    account_id=link.account_id,
                    identity_id=link.identity_id,
                    system=link.system,
                    username=link.username,
                    confidence=link.confidence,
                    reasons_json=json.dumps(link.reasons),
                    is_manual=1 if link.is_manual else 0,
                    status=link.status,
                )
            )

        # Insert Review Queue Items
        for item in result.review_queue:
            session.add(
                ReviewQueueRecord(
                    item_id=item.item_id,
                    run_id=run_id,
                    account_id=item.account_id,
                    suggested_identity_id=item.suggested_identity_id,
                    confidence=item.confidence,
                    reasons_json=json.dumps(item.reasons),
                    account_details_json=json.dumps(item.account_details),
                    identity_details_json=json.dumps(item.identity_details),
                    status=item.status,
                )
            )

        # Insert Account Classifications
        for cl in result.classifications:
            session.add(
                AccountClassificationRecord(
                    run_id=run_id,
                    account_id=cl.account_id,
                    system=cl.system,
                    username=cl.username,
                    classification=cl.classification,
                    reasons_json=json.dumps(cl.reasons),
                    inactivity_days=cl.inactivity_days,
                    owner=cl.owner,
                    risk_level=cl.risk_level,
                )
            )

        # Audit Log Entry
        session.add(
            AuditLogRecord(
                action="IDENTITY_RESOLUTION_EXECUTED",
                actor="engine",
                entity_type="run",
                entity_id=run_id,
                details_json=json.dumps({
                    "golden_identities": len(result.golden_identities),
                    "account_links": len(result.account_links),
                    "review_queue": len(result.review_queue),
                    "refused_merges": len(refused_merges),
                    "classifications": result.metrics,
                }),
            )
        )

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def manual_merge_identities(
    run_id: str,
    target_identity_id: str,
    source_identity_id: str,
    actor: str = "analyst",
) -> bool:
    """Manually merge two identities, moving all linked accounts to target_identity_id."""
    session = get_session()
    try:
        target = session.query(GoldenIdentityRecord).filter(
            GoldenIdentityRecord.run_id == run_id,
            GoldenIdentityRecord.identity_id == target_identity_id,
        ).first()

        source = session.query(GoldenIdentityRecord).filter(
            GoldenIdentityRecord.run_id == run_id,
            GoldenIdentityRecord.identity_id == source_identity_id,
        ).first()

        if not target or not source:
            return False

        # Constraint check: Cannot merge if differing non-null employee IDs
        if target.employee_id and source.employee_id and target.employee_id != source.employee_id:
            raise ValueError(
                f"Cannot merge identities with conflicting employee IDs ('{target.employee_id}' vs '{source.employee_id}')"
            )

        # Transfer linked accounts
        target_accounts = json.loads(target.linked_account_ids_json or "[]")
        source_accounts = json.loads(source.linked_account_ids_json or "[]")
        merged_accounts = list(set(target_accounts + source_accounts))
        target.linked_account_ids_json = json.dumps(merged_accounts)

        # Update AccountLink records
        session.query(AccountLinkRecord).filter(
            AccountLinkRecord.run_id == run_id,
            AccountLinkRecord.identity_id == source_identity_id,
        ).update({"identity_id": target_identity_id, "is_manual": 1})

        # Remove source identity
        session.delete(source)

        # Audit
        session.add(
            AuditLogRecord(
                action="IDENTITY_MANUAL_MERGE",
                actor=actor,
                entity_type="identity",
                entity_id=target_identity_id,
                details_json=json.dumps({
                    "merged_source_id": source_identity_id,
                    "accounts_transferred": len(source_accounts),
                }),
            )
        )
        session.commit()
        return True
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def manual_split_account(
    run_id: str,
    account_id: str,
    actor: str = "analyst",
) -> str | None:
    """Detach an account from its current golden identity into a newly synthesized identity."""
    session = get_session()
    try:
        link = session.query(AccountLinkRecord).filter(
            AccountLinkRecord.run_id == run_id,
            AccountLinkRecord.account_id == account_id,
        ).first()

        if not link:
            return None

        old_identity_id = link.identity_id
        old_gid = session.query(GoldenIdentityRecord).filter(
            GoldenIdentityRecord.run_id == run_id,
            GoldenIdentityRecord.identity_id == old_identity_id,
        ).first()

        if old_gid:
            accounts = json.loads(old_gid.linked_account_ids_json or "[]")
            if account_id in accounts:
                accounts.remove(account_id)
                old_gid.linked_account_ids_json = json.dumps(accounts)

        # Create new standalone golden identity
        new_identity_id = f"gid_split_{account_id}"
        new_gid = GoldenIdentityRecord(
            identity_id=new_identity_id,
            run_id=run_id,
            canonical_name=link.username,
            linked_account_ids_json=json.dumps([account_id]),
            confidence=1.0,
            sources_json=json.dumps([link.system]),
            employment_status="unlinked",
        )
        session.add(new_gid)

        # Update link
        link.identity_id = new_identity_id
        link.is_manual = 1
        link.reasons_json = json.dumps(["Manual split from identity " + old_identity_id])

        # Audit
        session.add(
            AuditLogRecord(
                action="ACCOUNT_MANUAL_SPLIT",
                actor=actor,
                entity_type="account",
                entity_id=account_id,
                details_json=json.dumps({
                    "detached_from_identity": old_identity_id,
                    "new_identity_id": new_identity_id,
                }),
            )
        )
        session.commit()
        return new_identity_id
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
