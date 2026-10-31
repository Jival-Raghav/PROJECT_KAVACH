"""
core/db.py — SQLAlchemy database models and SQLite run persistence for Kavach v2.
Manages runs, uploaded sources, mapping profiles, audit logs, and feedback loops.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config import get_settings
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class RunRecord(Base):
    __tablename__ = "runs"

    run_id = Column(String(64), primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    status = Column(String(32), default="pending")  # pending | running | complete | error
    source_hash = Column(String(64), nullable=True)
    mapping_profile_id = Column(String(64), nullable=True)
    summary_json = Column(Text, default="{}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "status": self.status,
            "source_hash": self.source_hash,
            "mapping_profile_id": self.mapping_profile_id,
            "summary": json.loads(self.summary_json or "{}"),
        }


class SourceRecord(Base):
    __tablename__ = "sources"

    source_id = Column(String(64), primary_key=True)
    filename = Column(String(256), nullable=False)
    file_type = Column(String(32), nullable=False)  # csv | json | parquet | sql
    row_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    profile_json = Column(Text, default="{}")


class MappingProfileRecord(Base):
    __tablename__ = "mapping_profiles"

    profile_id = Column(String(64), primary_key=True)
    version = Column(Integer, default=1)
    source_fingerprint = Column(String(64), nullable=False, index=True)
    role = Column(String(32), default="events")
    mappings_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    created_by = Column(String(64), default="system")
    notes = Column(Text, default="")


class MappingFeedbackRecord(Base):
    __tablename__ = "mapping_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    source_column = Column(String(128), nullable=False)
    target_field = Column(String(128), nullable=False)
    role = Column(String(32), default="field")
    transform_op = Column(String(64), default="identity")
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class AuditLogRecord(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC))
    action = Column(String(64), nullable=False)
    actor = Column(String(64), default="analyst")
    entity_type = Column(String(64), nullable=False)
    entity_id = Column(String(128), nullable=False)
    details_json = Column(Text, default="{}")


class PostureSnapshotRecord(Base):
    __tablename__ = "posture_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), nullable=False, index=True)
    score = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC))
    metrics_json = Column(Text, default="{}")


class GoldenIdentityRecord(Base):
    __tablename__ = "identities_golden"

    # Identity ids are deterministic, so they repeat across runs: the key is per-run.
    run_id = Column(String(64), primary_key=True)
    identity_id = Column(String(64), primary_key=True)
    canonical_name = Column(String(256), nullable=False)
    primary_email = Column(String(256), nullable=True)
    employee_id = Column(String(64), nullable=True, index=True)
    department = Column(String(128), nullable=True)
    job_title = Column(String(128), nullable=True)
    employment_status = Column(String(32), default="active")
    linked_account_ids_json = Column(Text, default="[]")
    confidence = Column(Float, default=1.0)
    sources_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class AccountLinkRecord(Base):
    __tablename__ = "account_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), nullable=False, index=True)
    account_id = Column(String(128), nullable=False, index=True)
    identity_id = Column(String(64), nullable=False, index=True)
    system = Column(String(64), nullable=False)
    username = Column(String(128), nullable=False)
    confidence = Column(Float, default=1.0)
    reasons_json = Column(Text, default="[]")
    is_manual = Column(Integer, default=0)
    status = Column(String(32), default="linked")  # linked | review | unlinked


class ReviewQueueRecord(Base):
    __tablename__ = "resolution_review_queue"

    item_id = Column(String(64), primary_key=True)
    run_id = Column(String(64), primary_key=True)
    account_id = Column(String(128), nullable=False)
    suggested_identity_id = Column(String(64), nullable=False)
    confidence = Column(Float, default=0.8)
    reasons_json = Column(Text, default="[]")
    account_details_json = Column(Text, default="{}")
    identity_details_json = Column(Text, default="{}")
    status = Column(String(32), default="pending")  # pending | accepted | rejected
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class AccountClassificationRecord(Base):
    __tablename__ = "account_classifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), nullable=False, index=True)
    account_id = Column(String(128), nullable=False, index=True)
    system = Column(String(64), nullable=False)
    username = Column(String(128), nullable=False)
    classification = Column(String(32), nullable=False)  # orphaned | leaver_active | dormant | service | shared | human
    reasons_json = Column(Text, default="[]")
    inactivity_days = Column(Integer, nullable=True)
    owner = Column(String(128), nullable=True)
    risk_level = Column(String(32), default="low")  # low | medium | high | critical



# ── Engine & Session Management ───────────────────────────────────────────────

_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_settings()
        db_path = Path(cfg.DB_PATH)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
        )
        _migrate_per_run_keys(_engine)
        Base.metadata.create_all(_engine)
    return _engine


def _migrate_per_run_keys(engine) -> None:
    """Databases created before the key became (run_id, id) rejected a second run with the same
    identity ids (UNIQUE constraint failed). Rebuild those tables with the per-run composite key."""
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    for table_name in ("identities_golden", "resolution_review_queue"):
        if not insp.has_table(table_name):
            continue
        pk = insp.get_pk_constraint(table_name).get("constrained_columns") or []
        if "run_id" in pk:
            continue
        cols = ", ".join(c["name"] for c in insp.get_columns(table_name))
        with engine.begin() as conn:
            for idx in insp.get_indexes(table_name):
                conn.execute(text(f'DROP INDEX IF EXISTS "{idx["name"]}"'))
            conn.execute(text(f'ALTER TABLE "{table_name}" RENAME TO "{table_name}_old"'))
            Base.metadata.tables[table_name].create(conn)
            conn.execute(text(f'INSERT INTO "{table_name}" ({cols}) SELECT {cols} FROM "{table_name}_old"'))
            conn.execute(text(f'DROP TABLE "{table_name}_old"'))


def get_session():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine())
    return _SessionFactory()


def init_db():
    get_engine()
