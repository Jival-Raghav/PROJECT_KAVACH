"""tests/test_da.py
Comprehensive unit tests for Phase 4: Evidence-Grounded Devil's Advocate Co-Pilot.

Tests:
1. Strict Pydantic argument validation for all 10 evidence tools.
2. Code-level citation enforcement (downgrading unevidenced refutations to 'unverifiable').
3. Non-negotiable hard-rule immutability (SoD and leaver violations forced to 'stands').
4. Deterministic doubt_score calculation.
5. Bounded severity adjustments (maximum 1-level drop normally, capped at REVIEW for hard rules).
6. End-to-end investigation refuting benign cases backed by org context.
7. End-to-end investigation confirming malicious cases and formulating concrete remediation.
"""
from __future__ import annotations

import pytest
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEvent,
    CanonicalIdentity,
    OrgContext,
)
from llm.devils_advocate import (
    ClaimRebuttal,
    calculate_doubt_score,
    compute_adjusted_severity,
    enforce_citations,
)
from llm.investigate import investigate_user
from llm.prosecutor import ProsecutorClaim
from llm.tools import execute_tool


@pytest.fixture
def da_bundle() -> CanonicalBundle:
    """Fixture with identities, accounts, events, and planted organizational context."""
    org_ctx = OrgContext(
        oncall=[
            {
                "user": "alice",
                "system": "PROD_DB",
                "start_time": "2026-03-25T00:00:00Z",
                "end_time": "2026-03-25T08:00:00Z",
                "role": "Primary SRE",
            }
        ],
        tickets=[
            {
                "ticket_id": "CHG-770",
                "user": "bob",
                "system": "CUSTOMER_DB",
                "start_time": "2026-03-25T12:00:00Z",
                "end_time": "2026-03-25T18:00:00Z",
                "status": "APPROVED",
            },
            {
                "ticket_id": "CHG-EXPIRED",
                "user": "malicious_user",
                "system": "PROD_DB",
                "start_time": "2026-03-25T00:00:00Z",
                "end_time": "2026-03-25T04:00:00Z",
                "status": "APPROVED",
            },
        ],
        projects=[
            {
                "project_id": "PRJ-99",
                "user": "alice",
                "system": "FINANCE_LAKE",
                "start_date": "2026-01-01",
                "end_date": "2026-12-31",
            }
        ],
        leave=[
            {
                "user": "carol",
                "start_date": "2026-03-20",
                "end_date": "2026-03-27",
            }
        ],
        hr_events=[
            {
                "user": "david",
                "event_type": "ROLE_TRANSFER",
                "effective_date": "2026-03-15",
            }
        ],
        exceptions=[
            {
                "exception_id": "EXC-101",
                "user": "eve",
                "entitlement": "aws_iam_admin",
                "expiry_date": "2026-06-30",
            }
        ],
    )

    identities = [
        CanonicalIdentity(identity_id="alice", full_name="Alice SRE", department="Engineering", job_title="SRE Lead"),
        CanonicalIdentity(identity_id="bob", full_name="Bob Admin", department="IT", job_title="DBA"),
        CanonicalIdentity(identity_id="malicious_user", full_name="Mallory Threat", department="Finance", job_title="Analyst"),
    ]

    accounts = [
        CanonicalAccount(account_id="acc_alice", system="PROD_DB", username="alice", privilege_level="admin", extra={"identity_id": "alice"}),
        CanonicalAccount(account_id="acc_bob", system="CUSTOMER_DB", username="bob", privilege_level="admin", extra={"identity_id": "bob"}),
        CanonicalAccount(account_id="acc_mal", system="PROD_DB", username="mallory", privilege_level="user", extra={"identity_id": "malicious_user"}),
    ]

    events = [
        CanonicalEvent(event_id="e1", timestamp="2026-03-25T03:00:00Z", user_key="alice", action="admin_operation", resource="PROD_DB", system="PROD_DB", resource_sensitivity="crown", success=True),
        CanonicalEvent(event_id="e2", timestamp="2026-03-25T14:00:00Z", user_key="bob", action="export_data", resource="CUSTOMER_DB", system="CUSTOMER_DB", resource_sensitivity="high", success=True),
        CanonicalEvent(event_id="e3", timestamp="2026-03-25T06:00:00Z", user_key="malicious_user", action="admin_operation", resource="PROD_DB", system="PROD_DB", resource_sensitivity="crown", success=True),
    ]

    return CanonicalBundle(
        run_id="test_da_bundle",
        identities=identities,
        accounts=accounts,
        entitlements=[],
        events=events,
        org_context=org_ctx,
    )


def test_tool_argument_validation(da_bundle: CanonicalBundle):
    """Verify strict Pydantic argument validation for evidence tools."""
    # 1. Valid invocation
    res_valid = execute_tool(
        da_bundle,
        "was_on_call",
        {"user": "alice", "ts": "2026-03-25T03:00:00Z", "system": "PROD_DB"},
    )
    assert res_valid["result"] is True
    assert len(res_valid["evidence_rows"]) == 1

    # 2. Invalid invocation: missing required 'ts'
    res_invalid = execute_tool(
        da_bundle,
        "was_on_call",
        {"user": "alice"},
    )
    assert res_invalid["result"] is False
    assert res_invalid["error"] == "InvalidArguments"

    # 3. Disallowed tool name
    res_disallowed = execute_tool(
        da_bundle,
        "arbitrary_dangerous_tool",
        {"arg": "val"},
    )
    assert res_disallowed["result"] is False
    assert res_disallowed["error"] == "DisallowedTool"


def test_citation_enforcement_downgrade():
    """Verify that claims marked refuted without valid supporting tool citations are downgraded."""
    claims = [
        ProsecutorClaim(claim_id="c1", type="sensitive_access", statement="Night export", severity="high", hard_rule=False),
        ProsecutorClaim(claim_id="c2", type="peer_outlier", statement="Peer deviation", severity="medium", hard_rule=False),
    ]

    # Rebuttal claims c1 is refuted citing call_1 (which was True), but c2 cites call_missing (non-existent)
    tool_results = [
        {"tool_call_id": "call_1", "tool": "was_on_call", "result": True, "evidence_rows": [{"id": 1}]},
        {"tool_call_id": "call_failed", "tool": "change_ticket_covering", "result": False, "evidence_rows": []},
    ]

    rebuttals = [
        ClaimRebuttal(claim_id="c1", status="refuted", cited_tool_call_ids=["call_1"], rationale="Approved oncall"),
        ClaimRebuttal(claim_id="c2", status="refuted", cited_tool_call_ids=["call_failed"], rationale="Supposedly covered"),
    ]

    verified = enforce_citations(claims, rebuttals, tool_results)

    reb_map = {r.claim_id: r for r in verified}
    assert reb_map["c1"].status == "refuted"
    # c2 cited a tool whose result was False -> auto-downgraded to unverifiable!
    assert reb_map["c2"].status == "unverifiable"


def test_hard_rule_refusal():
    """Verify that hard security rules (SoD violations) cannot be dismissed."""
    claims = [
        ProsecutorClaim(claim_id="c1", type="sod_conflict", statement="SoD fraud", severity="critical", hard_rule=True),
    ]
    tool_results = [
        {"tool_call_id": "call_ticket", "tool": "change_ticket_covering", "result": True, "evidence_rows": [{"ticket": "T1"}]},
    ]
    # Even if DA claims refuted with a valid tool citation, hard rule MUST force status to 'stands'
    rebuttals = [
        ClaimRebuttal(claim_id="c1", status="refuted", cited_tool_call_ids=["call_ticket"], rationale="User had ticket"),
    ]

    verified = enforce_citations(claims, rebuttals, tool_results)
    assert verified[0].status == "stands"
    assert verified[0].hard_rule is True
    assert "Hard security rule cannot be dismissed" in verified[0].rationale


def test_doubt_score_calculation():
    """Verify deterministic doubt score formula."""
    claims = [
        ProsecutorClaim(claim_id="c1", type="anomaly", statement="Claim 1", severity="critical"),  # weight 4.0
        ProsecutorClaim(claim_id="c2", type="anomaly", statement="Claim 2", severity="medium"),    # weight 2.0
    ]

    # Both refuted: (4*1.0 + 2*1.0) / 6 = 1.0
    rebuttals_all = [
        ClaimRebuttal(claim_id="c1", status="refuted", rationale=""),
        ClaimRebuttal(claim_id="c2", status="refuted", rationale=""),
    ]
    assert calculate_doubt_score(claims, rebuttals_all) == 1.0

    # c1 weakened (0.5), c2 stands (0.0): (4*0.5 + 2*0.0) / 6 = 2.0 / 6 = 0.3333
    rebuttals_partial = [
        ClaimRebuttal(claim_id="c1", status="weakened", rationale=""),
        ClaimRebuttal(claim_id="c2", status="stands", rationale=""),
    ]
    assert calculate_doubt_score(claims, rebuttals_partial) == pytest.approx(0.3333, abs=1e-3)


def test_severity_adjustment_bounds():
    """Verify bounded severity transitions."""
    claims_soft = [ProsecutorClaim(claim_id="c1", type="anomaly", statement="Alert", severity="high", hard_rule=False)]
    reb_refuted = [ClaimRebuttal(claim_id="c1", status="refuted", rationale="")]

    # High doubt (1.0) on soft claim drops 2 levels: CRITICAL -> REVIEW
    adj = compute_adjusted_severity("CRITICAL", claims_soft, reb_refuted, doubt_score=1.0)
    assert adj == "REVIEW"

    # Moderate doubt drops at most 1 level: CRITICAL -> HIGH
    adj_mod = compute_adjusted_severity("CRITICAL", claims_soft, reb_refuted, doubt_score=0.70)
    assert adj_mod == "HIGH"

    # When hard rule exists, NEVER drops below REVIEW
    claims_hard = [ProsecutorClaim(claim_id="c1", type="sod", statement="SoD", severity="critical", hard_rule=True)]
    adj_hard = compute_adjusted_severity("CRITICAL", claims_hard, reb_refuted, doubt_score=1.0)
    assert adj_hard == "REVIEW"


def test_end_to_end_benign_refutation(da_bundle: CanonicalBundle):
    """Verify Alice's night alert on PROD_DB is successfully refuted by oncall schedule."""
    verdict = investigate_user(da_bundle, "alice", use_llm=False)

    assert verdict.verdict == "MITIGATED_BENIGN"
    assert verdict.doubt_score >= 0.75
    # Citations must be recorded
    assert any(r.get("tool") == "was_on_call" and r.get("result") is True for r in verdict.tool_results)
    # Remediation step must be NO_ACTION
    assert verdict.remediation_steps[0].action == "NO_ACTION"


def test_end_to_end_malicious_stand(da_bundle: CanonicalBundle):
    """Verify Mallory's post-expiration access on PROD_DB stands as CONFIRMED_THREAT."""
    # Mallory accessed PROD_DB at 06:00, but ticket expired at 04:00
    verdict = investigate_user(da_bundle, "malicious_user", use_llm=False)

    assert verdict.verdict == "CONFIRMED_THREAT"
    assert verdict.doubt_score <= 0.35
    # Remediation must contain an actionable response (e.g. DISABLE_ACCOUNT)
    assert any(step.action in ("DISABLE_ACCOUNT", "REVOKE_ENTITLEMENT", "UPDATE_TICKET") for step in verdict.remediation_steps)
