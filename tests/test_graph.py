"""
tests/test_graph.py — Comprehensive Unit Tests for Identity Knowledge Graph, Blast Radius & What-If.
"""
from __future__ import annotations

import pytest
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEntitlement,
    CanonicalEvent,
    CanonicalIdentity,
    CanonicalSystem,
)
from graph.build import build_identity_graph
from graph.blast import compute_blast_radius
from graph.paths import find_attack_paths_to_crown_jewels
from graph.toxic import detect_toxic_combinations
from graph.whatif import simulate_whatif_revoke


@pytest.fixture
def graph_bundle() -> CanonicalBundle:
    identities = [
        CanonicalIdentity(
            identity_id="ID_ALICE",
            employee_id="E001",
            full_name="Alice Smith",
            email="alice@megacorp.com",
            department="Engineering",
            job_title="Lead Architect",
            employment_status="active",
            source="workday",
        ),
        CanonicalIdentity(
            identity_id="ID_BOB",
            employee_id="E002",
            full_name="Bob Jones",
            email="bob@megacorp.com",
            department="Finance",
            job_title="Financial Analyst",
            employment_status="active",
            source="workday",
        ),
    ]

    systems = [
        CanonicalSystem(system="AWS_PROD", sensitivity="crown", owner="Cloud Team"),
        CanonicalSystem(system="JIRA", sensitivity="low", owner="IT"),
        CanonicalSystem(system="SAP_ERP", sensitivity="crown", owner="Finance Ops"),
    ]

    accounts = [
        CanonicalAccount(
            account_id="ACC_ALICE_AWS",
            system="AWS_PROD",
            username="asmith_aws",
            email="alice@megacorp.com",
            employee_id_hint="E001",
            account_type="admin",
            status="active",
            privilege_level="admin",
            source="aws_iam",
        ),
        CanonicalAccount(
            account_id="ACC_BOB_SAP_1",
            system="SAP_ERP",
            username="bjones_vendor",
            email="bob@megacorp.com",
            employee_id_hint="E002",
            account_type="human",
            status="active",
            privilege_level="standard",
            source="sap",
        ),
        CanonicalAccount(
            account_id="ACC_BOB_SAP_2",
            system="SAP_ERP",
            username="bjones_pay",
            email="bob@megacorp.com",
            employee_id_hint="E002",
            account_type="human",
            status="active",
            privilege_level="elevated",
            source="sap",
        ),
    ]

    entitlements = [
        CanonicalEntitlement(
            account_id="ACC_ALICE_AWS",
            system="AWS_PROD",
            entitlement="AdministratorAccess",
            privilege_weight=10,
        ),
        CanonicalEntitlement(
            account_id="ACC_BOB_SAP_1",
            system="SAP_ERP",
            entitlement="create_vendor",
            privilege_weight=5,
        ),
        CanonicalEntitlement(
            account_id="ACC_BOB_SAP_2",
            system="SAP_ERP",
            entitlement="approve_payment",
            privilege_weight=8,
        ),
    ]

    events = [
        CanonicalEvent(
            event_id="EV01",
            timestamp="2026-10-15T12:00:00Z",
            user_key="ACC_ALICE_AWS",
            action="assume_role",
            system="AWS_PROD",
            resource="CUSTOMER_DB_ENCRYPTION_KEY",
            resource_sensitivity="crown",
            source_ip="10.0.0.1",
        )
    ]

    return CanonicalBundle(
        identities=identities,
        systems=systems,
        accounts=accounts,
        entitlements=entitlements,
        events=events,
    )


def test_graph_build(graph_bundle):
    g = build_identity_graph(graph_bundle)
    assert g.number_of_nodes() > 0
    assert g.number_of_edges() > 0

    assert "identity:ID_ALICE" in g
    assert "account:ACC_ALICE_AWS" in g
    assert "system:AWS_PROD" in g
    assert "resource:AWS_PROD:CUSTOMER_DB_ENCRYPTION_KEY" in g

    # Check edges
    assert g.has_edge("identity:ID_ALICE", "account:ACC_ALICE_AWS")
    assert g.has_edge("account:ACC_ALICE_AWS", "entitlement:AWS_PROD:AdministratorAccess")
    assert g.has_edge("entitlement:AWS_PROD:AdministratorAccess", "system:AWS_PROD")


def test_blast_radius_computation(graph_bundle):
    g = build_identity_graph(graph_bundle)
    blast = compute_blast_radius(g, "account:ACC_ALICE_AWS")

    assert blast["blast_score"] > 0
    assert len(blast["crown_jewels"]) >= 1
    crown_names = [c["name"] for c in blast["crown_jewels"]]
    assert "AWS_PROD" in crown_names or "CUSTOMER_DB_ENCRYPTION_KEY" in crown_names


def test_attack_paths_to_crown_jewels(graph_bundle):
    g = build_identity_graph(graph_bundle)
    paths = find_attack_paths_to_crown_jewels(g, "identity:ID_ALICE")

    assert len(paths) >= 1
    top_path = paths[0]
    assert top_path["source"] == "identity:ID_ALICE"
    assert top_path["total_cost"] > 0
    assert len(top_path["nodes"]) >= 3


def test_toxic_combinations_multi_hop_sod(graph_bundle):
    g = build_identity_graph(graph_bundle)
    findings = detect_toxic_combinations(graph_bundle, g)

    # Bob holds create_vendor on ACC_BOB_SAP_1 and approve_payment on ACC_BOB_SAP_2
    assert len(findings) >= 1
    bob_finding = [f for f in findings if f["identity_id"] == "ID_BOB"][0]
    assert bob_finding["finding_type"] == "multi_hop_sod"
    assert "create_vendor" in bob_finding["conflict"]
    assert "approve_payment" in bob_finding["conflict"]


def test_whatif_revoke_simulation(graph_bundle):
    g = build_identity_graph(graph_bundle)
    res = simulate_whatif_revoke(
        graph_bundle,
        g,
        revocations=[{"account_id": "ACC_ALICE_AWS", "entitlement": "AdministratorAccess"}],
        replay_days=60,
    )

    assert res["status"] == "success"
    assert "metrics" in res
    metrics = res["metrics"]
    assert metrics["blast_score_before"] >= metrics["blast_score_after"]
    assert metrics["paths_eliminated"] >= 0
    assert len(res["revocations"]) == 1
    assert res["revocations"][0]["account_id"] == "ACC_ALICE_AWS"
