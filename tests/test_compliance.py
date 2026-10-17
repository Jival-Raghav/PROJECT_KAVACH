"""
tests/test_compliance.py — Unit Tests for Posture Score, Compliance Controls & Audit Pack Exporter.
"""
from __future__ import annotations

import json
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEntitlement,
    CanonicalIdentity,
    CanonicalSystem,
)
from posture.compliance import evaluate_compliance, load_control_catalog
from posture.report import (
    generate_audit_pack_csv,
    generate_audit_pack_json,
    generate_audit_pack_pdf,
)
from posture.score import calculate_identity_hygiene_score


def test_control_catalog_loading():
    controls = load_control_catalog()
    assert len(controls) >= 8
    fws = {c["framework"] for c in controls}
    assert "NIST SP 800-53" in fws
    assert "ISO/IEC 27001:2022" in fws
    assert "India DPDP Act 2023" in fws


def test_hygiene_score_and_dynamic_reweighting():
    bundle = CanonicalBundle(
        identities=[
            CanonicalIdentity(
                identity_id="ID_01",
                employee_id="E01",
                full_name="Alice Compliance",
                employment_status="active",
                source="hr",
            )
        ],
        systems=[CanonicalSystem(system="CLOUD", sensitivity="high")],
        accounts=[
            CanonicalAccount(
                account_id="ACC_01",
                system="CLOUD",
                username="alice_c",
                privilege_level="admin",
                mfa_enabled=True,
                source="iam",
            )
        ],
        entitlements=[
            CanonicalEntitlement(
                account_id="ACC_01",
                system="CLOUD",
                entitlement="CloudAdmin",
                privilege_weight=10,
            )
        ],
    )

    res = calculate_identity_hygiene_score(bundle)
    assert 0.0 <= res["identity_hygiene_score"] <= 100.0
    assert "grade" in res
    assert "subscores" in res
    assert "insurer_exposure" in res
    assert res["insurer_exposure"]["tier"] in ("LOW", "ELEVATED", "CRITICAL")

    # Verify active weights sum to 100
    total_weights = sum(res["active_weights"].values())
    assert 99.0 <= total_weights <= 101.0


def test_compliance_evaluation_end_to_end():
    bundle = CanonicalBundle(
        identities=[
            CanonicalIdentity(
                identity_id="ID_TERM",
                employee_id="E99",
                full_name="Terminated User",
                employment_status="terminated",
                source="hr",
            )
        ],
        accounts=[
            CanonicalAccount(
                account_id="ACC_TERM",
                system="CORE",
                username="term_user",
                status="active",
                employee_id_hint="E99",
                source="ad",
            )
        ],
    )

    compliance = evaluate_compliance(bundle)
    assert compliance["status"] == "success"
    assert compliance["total_controls"] >= 8

    # Leaver is active -> NIST-AC-2 must fail
    ac2 = [c for c in compliance["controls"] if c["id"] == "NIST-AC-2"][0]
    assert ac2["status"] == "fail"


def test_audit_pack_exports():
    bundle = CanonicalBundle(
        identities=[
            CanonicalIdentity(identity_id="ID_01", employee_id="E01", source="hr")
        ],
        accounts=[
            CanonicalAccount(account_id="ACC_01", system="AWS", username="u1", source="iam")
        ],
    )

    hygiene = calculate_identity_hygiene_score(bundle)
    compliance = evaluate_compliance(bundle, hygiene)

    # 1. JSON
    json_str = generate_audit_pack_json(bundle, hygiene, compliance)
    parsed = json.loads(json_str)
    assert parsed["ispad_version"] == "v2.0-cyberforge"
    assert "manifest_sha256" in parsed
    assert len(parsed["manifest_sha256"]) == 64

    # 2. CSV
    csv_str = generate_audit_pack_csv(compliance)
    assert "Control_ID,Framework,Title,Status" in csv_str
    assert "NIST-AC-2" in csv_str

    # 3. PDF
    pdf_bytes = generate_audit_pack_pdf(bundle, hygiene, compliance)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
