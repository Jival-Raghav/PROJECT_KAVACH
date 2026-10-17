"""tests/test_resolution.py
Comprehensive unit and integration test suite for Feature 1b: Identity Resolution Engine.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalIdentity,
)
from resolve.blocking import build_candidate_pairs, generate_blocking_keys
from resolve.classify import classify_accounts
from resolve.cluster import ConstrainedUnionFind, build_golden_clusters
from resolve.engine import manual_split_account, run_identity_resolution
from resolve.match import compute_pair_score
from resolve.normalize import (
    derive_name_from_identifier,
    expand_name_variants,
    extract_email_local_part,
    get_initials_and_surname,
    normalize_name,
    strip_accents,
    strip_trailing_digits,
)


# ── 1. Normalization Tests ───────────────────────────────────────────────────


def test_strip_accents():
    assert strip_accents("René Müller") == "Rene Muller"
    assert strip_accents("Hélène François") == "Helene Francois"
    assert strip_accents("") == ""


def test_normalize_name():
    assert normalize_name("Müller, René") == "rene muller"
    assert normalize_name("  John   Doe  ") == "john doe"
    assert normalize_name("Smith, Jane-Anne") == "jane-anne smith"


def test_extract_email_local_part():
    assert extract_email_local_part("alice.smith@corp.com") == "alice.smith"
    assert extract_email_local_part("CORP\\alice.smith") == "alice.smith"
    assert extract_email_local_part("asmith") == "asmith"


def test_strip_trailing_digits():
    assert strip_trailing_digits("jraghav2") == "jraghav"
    assert strip_trailing_digits("asmith01") == "asmith"
    assert strip_trailing_digits("10042") == "10042"  # Pure numeric untouched


def test_nickname_expansion():
    variants_bob = expand_name_variants("bob")
    assert "robert" in variants_bob
    assert "bob" in variants_bob
    assert "rob" in variants_bob

    variants_bill = expand_name_variants("william")
    assert "bill" in variants_bill
    assert "billy" in variants_bill

    variants_beth = expand_name_variants("elizabeth")
    assert "beth" in variants_beth
    assert "liz" in variants_beth


def test_derive_name_from_identifier():
    assert derive_name_from_identifier("bob.davis@corp.com") == "bob davis"
    assert derive_name_from_identifier("beth_montgomery") == "beth montgomery"
    assert derive_name_from_identifier("ext_consultant_1") == "ext consultant 1"
    assert derive_name_from_identifier("rdavis99") == "rdavis99"


def test_initials_and_surname():
    init, sur = get_initials_and_surname("Robert Davis")
    assert init == "r"
    assert sur == "davis"

    init, sur = get_initials_and_surname("Alexander")
    assert init == "a"
    assert sur == "alexander"


# ── 2. Blocking Tests ─────────────────────────────────────────────────────────


def test_generate_blocking_keys():
    rec = {
        "employee_id": "E1001",
        "full_name": "Robert Davis",
        "email": "robert.davis@corp.com",
    }
    keys = generate_blocking_keys(rec)
    assert "emp:e1001" in keys
    assert "surname:davis" in keys
    assert "init_sur:r_davis" in keys
    assert "nick_sur:bob_davis" in keys


def test_build_candidate_pairs():
    records = [
        {"_record_id": "r1", "employee_id": "E1001", "full_name": "Robert Davis"},
        {"_record_id": "r2", "employee_id_hint": "E1001", "username": "rdavis"},
        {"_record_id": "r3", "employee_id": "E9999", "full_name": "Unrelated Person"},
    ]
    pairs = build_candidate_pairs(records, id_key="_record_id")
    assert ("r1", "r2") in pairs
    assert ("r1", "r3") not in pairs


# ── 3. Match Scoring Tests ───────────────────────────────────────────────────


def test_deterministic_employee_id_match():
    score, reasons = compute_pair_score(
        {"employee_id": "E1001", "full_name": "Alice Smith"},
        {"employee_id": "E1001", "username": "asmith"},
    )
    assert score == 1.0
    assert any("employee ID" in r for r in reasons)


def test_deterministic_email_match():
    score, reasons = compute_pair_score(
        {"email": "alice.smith@corp.com", "full_name": "Alice Smith"},
        {"email": "alice.smith@corp.com", "username": "asmith"},
    )
    assert score == 1.0
    assert any("corporate email" in r for r in reasons)


def test_conflicting_employee_id_refusal():
    score, reasons = compute_pair_score(
        {"employee_id": "E1001", "full_name": "Daniel Craig"},
        {"employee_id": "E2002", "full_name": "Daniel Craig"},
    )
    assert score == 0.0
    assert any("conflicting employee IDs" in r for r in reasons)


def test_nickname_surname_match():
    score, reasons = compute_pair_score(
        {"full_name": "Robert Davis", "email": "robert.davis@corp.com"},
        {"username": "bob.davis", "email": "bdavis@corp.com"},
    )
    assert score >= 0.94
    assert any("Nickname" in r for r in reasons)


def test_flast_username_match():
    score, reasons = compute_pair_score(
        {"full_name": "Robert Davis"},
        {"username": "rdavis99"},
    )
    assert score >= 0.94
    assert any("Username format" in r for r in reasons)


def test_differing_numbered_suffixes():
    score, reasons = compute_pair_score(
        {"username": "ext_consultant_1"},
        {"username": "ext_consultant_2"},
    )
    assert score <= 0.10
    assert any("conflicting account number" in r for r in reasons)


def test_distinct_people_same_surname():
    score, reasons = compute_pair_score(
        {"full_name": "John Smith"},
        {"full_name": "Jane Smith"},
    )
    assert score < 0.60


# ── 4. Constrained Union-Find Tests ──────────────────────────────────────────


def test_constrained_union_find_refusal():
    cuf = ConstrainedUnionFind()
    cuf.add("id_1", employee_id="E1001")
    cuf.add("id_2", employee_id="E1002")

    allowed, reason = cuf.can_union("id_1", "id_2")
    assert not allowed
    assert "conflicting employee IDs" in (reason or "")

    success = cuf.union("id_1", "id_2")
    assert not success
    assert len(cuf.refused_merges) == 1


def test_constrained_union_find_success():
    cuf = ConstrainedUnionFind()
    cuf.add("id_1", employee_id="E1001")
    cuf.add("acc_1", employee_id=None)
    cuf.add("acc_2", employee_id="E1001")

    # Merge acc_1 with id_1 -> root inherits E1001
    assert cuf.union("id_1", "acc_1")
    # Merge acc_2 with acc_1 -> both carry E1001
    assert cuf.union("acc_1", "acc_2")

    clusters = cuf.get_clusters()
    root = cuf.find("id_1")
    assert set(clusters[root]) == {"id_1", "acc_1", "acc_2"}


# ── 5. Account Classification Tests ──────────────────────────────────────────


def test_classify_leaver_active():
    now = datetime.now(UTC)
    term_date = (now - timedelta(days=30)).isoformat()

    ident = CanonicalIdentity(
        identity_id="id_leaver",
        employee_id="E_TERM",
        full_name="Terminated Employee",
        employment_status="terminated",
        termination_date=term_date,
    )
    acc = CanonicalAccount(
        account_id="acc_leaver",
        system="aws",
        username="term_emp",
        employee_id_hint="E_TERM",
        status="active",
    )
    goldens, links, _, _ = build_golden_clusters([ident], [acc], scored_pairs=[])
    classifications = classify_accounts([acc], [ident], goldens)

    assert len(classifications) == 1
    assert classifications[0].classification == "leaver_active"
    assert classifications[0].risk_level == "critical"


def test_classify_orphaned():
    acc = CanonicalAccount(
        account_id="acc_orphan",
        system="jira",
        username="unowned_guest",
        status="active",
    )
    goldens, _, _, _ = build_golden_clusters([], [acc], scored_pairs=[])
    classifications = classify_accounts([acc], [], goldens)

    assert len(classifications) == 1
    assert classifications[0].classification == "orphaned"
    assert classifications[0].risk_level in ("medium", "high")


def test_classify_dormant():
    now = datetime.now(UTC)
    acc = CanonicalAccount(
        account_id="acc_dormant",
        system="crm",
        username="stale_user",
        status="active",
        last_login=(now - timedelta(days=120)).isoformat(),
    )
    ident = CanonicalIdentity(
        identity_id="id_active",
        employee_id="E_ACTIVE",
        full_name="Active Person",
        employment_status="active",
    )
    acc.employee_id_hint = "E_ACTIVE"
    goldens, _, _, _ = build_golden_clusters([ident], [acc], scored_pairs=[])
    classifications = classify_accounts([acc], [ident], goldens, reference_time=now)

    assert len(classifications) == 1
    assert classifications[0].classification == "dormant"
    assert classifications[0].inactivity_days >= 120


def test_classify_service_account():
    acc = CanonicalAccount(
        account_id="acc_svc",
        system="k8s",
        username="svc_ci_deployer",
        status="active",
    )
    goldens, _, _, _ = build_golden_clusters([], [acc], scored_pairs=[])
    classifications = classify_accounts([acc], [], goldens)

    assert len(classifications) == 1
    assert classifications[0].classification == "service"


# ── 6. Manual Actions & Engine Integration ────────────────────────────────────


def test_resolution_engine_end_to_end():
    bundle = CanonicalBundle(
        run_id="test_run_e2e",
        identities=[
            CanonicalIdentity(
                identity_id="id_1",
                employee_id="E1001",
                full_name="Robert Davis",
                email="robert.davis@corp.com",
            )
        ],
        accounts=[
            CanonicalAccount(
                account_id="acc_1",
                system="okta",
                username="rdavis",
                email="robert.davis@corp.com",
                employee_id_hint="E1001",
            ),
            CanonicalAccount(
                account_id="acc_2",
                system="aws",
                username="bob.davis",
                email="bdavis@corp.com",
            ),
        ],
    )
    res = run_identity_resolution(bundle, persist=True)

    assert res.run_id == "test_run_e2e"
    assert len(res.golden_identities) == 1
    assert res.golden_identities[0].identity_id == "id_1"
    assert set(res.golden_identities[0].linked_account_ids) == {"acc_1", "acc_2"}

    # Test manual split
    new_gid = manual_split_account(run_id="test_run_e2e", account_id="acc_2", actor="test_runner")
    assert new_gid is not None
    assert new_gid.startswith("gid_split_")
