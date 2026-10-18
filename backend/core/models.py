"""
core/models.py — Canonical data model for Kavach v2.
All downstream detection, graph, and LLM reasoning consume ONLY these models.
Column names appear nowhere else outside the ingestion/adapter layer.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CanonicalIdentity(BaseModel):
    identity_id: str
    employee_id: str | None = None
    full_name: str | None = None
    email: str | None = None
    department: str | None = None
    job_title: str | None = None
    manager_id: str | None = None
    employment_status: str | None = "active"  # active | terminated | leave | contractor
    hire_date: str | None = None
    termination_date: str | None = None
    location: str | None = None
    source: str = "default"
    extra: dict[str, Any] = Field(default_factory=dict)


class CanonicalAccount(BaseModel):
    account_id: str
    system: str
    username: str
    email: str | None = None
    employee_id_hint: str | None = None
    account_type: str | None = "human"  # human | service | shared | admin
    status: str | None = "active"  # active | disabled
    created_at: str | None = None
    last_login: str | None = None
    mfa_enabled: bool | None = None
    privilege_level: str | None = "standard"  # none | standard | elevated | admin
    source: str = "default"
    extra: dict[str, Any] = Field(default_factory=dict)


class CanonicalEntitlement(BaseModel):
    account_id: str
    system: str
    entitlement: str
    privilege_weight: float | None = 1.0  # 0 to 10 scale
    granted_at: str | None = None
    granted_by: str | None = None
    last_used: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class CanonicalEvent(BaseModel):
    event_id: str
    timestamp: str  # ISO UTC
    user_key: str  # maps to account username or identity_id
    action: str
    resource: str | None = None
    system: str | None = None
    resource_sensitivity: str | None = "low"  # low | medium | high | crown
    success: bool = True
    source_ip: str | None = None
    geo: str | None = None
    device: str | None = None
    user_agent: str | None = None
    label: bool | None = None  # ground truth anomaly marker if available
    raw: dict[str, Any] = Field(default_factory=dict)
    extra: dict[str, Any] = Field(default_factory=dict)


class CanonicalSystem(BaseModel):
    system: str
    sensitivity: str = "low"  # low | medium | high | crown
    owner: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class OrgContext(BaseModel):
    oncall: list[dict[str, Any]] = Field(default_factory=list)
    leave: list[dict[str, Any]] = Field(default_factory=list)
    tickets: list[dict[str, Any]] = Field(default_factory=list)
    projects: list[dict[str, Any]] = Field(default_factory=list)
    hr_events: list[dict[str, Any]] = Field(default_factory=list)
    exceptions: list[dict[str, Any]] = Field(default_factory=list)


class CanonicalBundle(BaseModel):
    run_id: str = "default"
    identities: list[CanonicalIdentity] = Field(default_factory=list)
    accounts: list[CanonicalAccount] = Field(default_factory=list)
    entitlements: list[CanonicalEntitlement] = Field(default_factory=list)
    events: list[CanonicalEvent] = Field(default_factory=list)
    systems: list[CanonicalSystem] = Field(default_factory=list)
    org_context: OrgContext = Field(default_factory=OrgContext)

    def get_events_for_user(self, user_key: str) -> list[CanonicalEvent]:
        target = str(user_key).strip().lower()
        return [
            ev for ev in self.events
            if str(ev.user_key).strip().lower() == target
        ]

    def get_accounts_for_identity(self, identity_id: str) -> list[CanonicalAccount]:
        target = str(identity_id).strip().lower()
        return [
            acc for acc in self.accounts
            if str(acc.extra.get("identity_id", "")).strip().lower() == target
            or str(acc.account_id).strip().lower() == target
        ]

    def get_entitlements_for_account(self, account_id: str) -> list[CanonicalEntitlement]:
        target = str(account_id).strip().lower()
        return [
            ent for ent in self.entitlements
            if str(ent.account_id).strip().lower() == target
        ]


# ── Feature 1b: Identity Resolution Models ───────────────────────────────────


class GoldenIdentity(BaseModel):
    identity_id: str
    canonical_name: str
    primary_email: str | None = None
    employee_id: str | None = None
    department: str | None = None
    job_title: str | None = None
    employment_status: str | None = "active"
    linked_account_ids: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    sources: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class AccountLink(BaseModel):
    account_id: str
    identity_id: str
    system: str
    username: str
    confidence: float
    reasons: list[str] = Field(default_factory=list)
    is_manual: bool = False
    status: str = "linked"  # linked | review | unlinked


class ReviewQueueItem(BaseModel):
    item_id: str
    account_id: str
    suggested_identity_id: str
    confidence: float
    reasons: list[str] = Field(default_factory=list)
    account_details: dict[str, Any] = Field(default_factory=dict)
    identity_details: dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"  # pending | accepted | rejected


class AccountClassification(BaseModel):
    account_id: str
    system: str
    username: str
    classification: str  # orphaned | leaver_active | dormant | service | shared | human
    reasons: list[str] = Field(default_factory=list)
    inactivity_days: int | None = None
    owner: str | None = None
    risk_level: str = "low"  # low | medium | high | critical


class ResolutionResult(BaseModel):
    run_id: str
    golden_identities: list[GoldenIdentity] = Field(default_factory=list)
    account_links: list[AccountLink] = Field(default_factory=list)
    review_queue: list[ReviewQueueItem] = Field(default_factory=list)
    classifications: list[AccountClassification] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)

