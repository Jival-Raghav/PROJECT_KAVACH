"""
core/audit.py — Audit logging service for all human actions, schema edits, and remediations.
"""
from __future__ import annotations

import json
from typing import Any

from core.db import AuditLogRecord, get_session


def log_audit_event(
    action: str,
    entity_type: str,
    entity_id: str,
    actor: str = "analyst",
    details: dict[str, Any] | None = None,
) -> int:
    """Records an immutable audit event in the database."""
    session = get_session()
    try:
        record = AuditLogRecord(
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id),
            actor=actor,
            details_json=json.dumps(details or {}),
        )
        session.add(record)
        session.commit()
        return record.id
    finally:
        session.close()


def get_audit_events(
    limit: int = 100,
    entity_type: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieves the most recent audit records."""
    session = get_session()
    try:
        query = session.query(AuditLogRecord)
        if entity_type:
            query = query.filter(AuditLogRecord.entity_type == entity_type)
        records = query.order_by(AuditLogRecord.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "action": r.action,
                "actor": r.actor,
                "entity_type": r.entity_type,
                "entity_id": r.entity_id,
                "details": json.loads(r.details_json or "{}"),
            }
            for r in records
        ]
    finally:
        session.close()
