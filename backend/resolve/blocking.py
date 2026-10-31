"""backend/resolve/blocking.py
Multi-key candidate pair blocking engine.
Avoids O(N^2) exhaustive pairwise comparisons by partitioning records across
employee IDs, email local-part prefixes, surnames, and initials.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from resolve.normalize import (
    derive_name_from_identifier,
    expand_name_variants,
    extract_email_local_part,
    get_initials_and_surname,
    strip_trailing_digits,
    tokenize_name,
)


def generate_blocking_keys(record: dict[str, Any]) -> set[str]:
    """Generate a set of blocking keys for an identity or account record."""
    keys: set[str] = set()

    # 1. Employee ID block
    emp_id = record.get("employee_id") or record.get("employee_id_hint")
    if emp_id:
        keys.add(f"emp:{str(emp_id).strip().lower()}")

    # 2. Email local-part prefix
    email = record.get("email")
    username = record.get("username") or record.get("user_key")

    local_email = extract_email_local_part(email) if email else ""
    local_user = extract_email_local_part(username) if username else ""

    for l_part in (local_email, local_user):
        if l_part:
            base = strip_trailing_digits(l_part.replace(".", "").replace("_", ""))
            if len(base) >= 3:
                keys.add(f"local:{base[:4]}")
                keys.add(f"base:{base}")

            # Also check flast format (e.g. rdavis -> r + davis, millerd -> miller + d)
            if len(base) >= 5 and base.isalpha():
                keys.add(f"init_sur:{base[0]}_{base[1:]}")
                keys.add(f"surname:{base[1:]}")
                keys.add(f"init_sur:{base[-1]}_{base[:-1]}")
                keys.add(f"surname:{base[:-1]}")

    # 3. Name tokens, surname, and nickname aliases
    full_name = record.get("full_name") or record.get("name")
    if not full_name:
        # Derive candidate name from username or email local-part
        full_name = derive_name_from_identifier(username or local_email)

    if full_name:
        tokens = tokenize_name(full_name)
        initial, surname = get_initials_and_surname(full_name)

        if len(surname) >= 3:
            keys.add(f"surname:{surname}")
        if initial and len(surname) >= 3:
            keys.add(f"init_sur:{initial}_{surname}")

        for t in tokens:
            if len(t) >= 4:
                keys.add(f"token:{t}")

        # Add nickname alias blocks: e.g. Robert Davis -> nick_sur:bob_davis
        if tokens and len(surname) >= 3:
            first_token = tokens[0]
            for variant in expand_name_variants(first_token):
                keys.add(f"nick_sur:{variant}_{surname}")

    return keys



def build_candidate_pairs(
    records: list[dict[str, Any]],
    id_key: str = "_record_id",
) -> set[tuple[str, str]]:
    """Index records across blocking keys and return candidate pairs (id_a, id_b) with a < b."""
    inverted_index: dict[str, list[str]] = defaultdict(list)

    for r in records:
        rec_id = str(r.get(id_key) or r.get("id") or "")
        if not rec_id:
            continue
        b_keys = generate_blocking_keys(r)
        for k in b_keys:
            inverted_index[k].append(rec_id)

    candidate_pairs: set[tuple[str, str]] = set()

    for k, ids in inverted_index.items():
        # Avoid massive blocks that produce too many pairs (cardinality cap)
        if len(ids) > 100:
            continue
        n = len(ids)
        for i in range(n):
            for j in range(i + 1, n):
                id_a, id_b = ids[i], ids[j]
                if id_a != id_b:
                    pair = (id_a, id_b) if id_a < id_b else (id_b, id_a)
                    candidate_pairs.add(pair)

    return candidate_pairs


generate_candidate_pairs = build_candidate_pairs

