"""backend/ingest/unified_schema.py
Domain models and schema definitions for the Unified Schema Editor.
Represents multi-source join graphs, unified field states, provenance, and edit operations.
"""
from __future__ import annotations

import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class RoleEnum(str, Enum):
    IDENTIFIER = "identifier"
    TIMESTAMP = "timestamp"
    ACTOR = "actor"
    ACTION = "action"
    RESOURCE = "resource"
    SENSITIVITY = "sensitivity"
    PRIVILEGE = "privilege"
    PEER_GROUP = "peer_group"
    FEATURE = "feature"
    CONTEXT_ONLY = "context_only"
    LABEL = "label"
    IGNORE = "ignore"


class ProvenanceEnum(str, Enum):
    AI = "ai"
    HUMAN_ADDED = "human_added"
    HUMAN_EDITED = "human_edited"
    HUMAN_REMOVED = "human_removed"


class OriginEnum(str, Enum):
    CANONICAL = "canonical"
    DERIVED = "derived"
    CUSTOM = "custom"
    PASSTHROUGH = "passthrough"


class UnifiedField(BaseModel):
    field_name: str
    origin: str = OriginEnum.CANONICAL.value
    source_refs: list[str] = Field(default_factory=list)  # e.g. ["source_1.column_a"]
    dtype: str = "string"
    role: str = RoleEnum.FEATURE.value
    include: bool = True
    pii: bool = False
    description: str = ""
    confidence: float = 0.9
    provenance: str = ProvenanceEnum.AI.value
    expression: str | None = None  # DSL expression if origin == "derived"


class JoinEdge(BaseModel):
    id: str
    left_source: str
    right_source: str
    left_keys: list[str]
    right_keys: list[str]
    join_type: str = "left"  # left | inner | outer
    cardinality: str = "many-to-one"
    match_rate: float = 0.0
    unmatched_samples: list[Any] = Field(default_factory=list)
    confidence: float = 0.85


class EditOp(BaseModel):
    op: str
    params: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    actor: str = "analyst"


class UnifiedSchema(BaseModel):
    id: str
    version: int = 1
    sources: list[str] = Field(default_factory=list)
    joins: list[JoinEdge] = Field(default_factory=list)
    fields: list[UnifiedField] = Field(default_factory=list)
    edit_log: list[EditOp] = Field(default_factory=list)
    ai_proposal_json: str = ""  # Snapshot of original AI proposal for reset & diff
