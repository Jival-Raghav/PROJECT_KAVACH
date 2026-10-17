"""backend/resolve/match.py
Pairwise similarity scoring and deterministic linking for Identity Resolution.
Evaluates Jaro-Winkler distance, token set ratios, nickname aliases, initials+surname,
username conventions (flast, lastf), and organizational alignment.
"""
from __future__ import annotations

from typing import Any

import rapidfuzz.distance.JaroWinkler as jw
import rapidfuzz.fuzz as fuzz

from resolve.normalize import (
    derive_name_from_identifier,
    expand_name_variants,
    extract_email_local_part,
    get_initials_and_surname,
    normalize_name,
    strip_trailing_digits,
    tokenize_name,
)


def _evaluate_first_name_match(first_a: str, first_b: str) -> tuple[bool, float, str]:
    """Compare first names across exact, nickname aliases, fuzzy typos, and initials."""
    if not first_a or not first_b:
        return False, 0.0, "Missing first name"

    fa = first_a.lower().strip()
    fb = first_b.lower().strip()

    if fa == fb:
        return True, 1.0, "Exact first name match"

    vars_a = expand_name_variants(fa)
    if fb in vars_a:
        return True, 0.96, f"Nickname alias match ('{fa}' ↔ '{fb}')"

    # Fuzzy typo check (e.g. Alexandre vs Alexander)
    sim = jw.similarity(fa, fb)
    if sim >= 0.88:
        return True, sim, f"Fuzzy first name similarity ({int(sim * 100)}%)"

    # Initial matching: only apply if one is a single initial
    if len(fa) == 1 or len(fb) == 1:
        if fa[0] == fb[0]:
            return True, 0.92, f"Initial match ('{fa[0]}')"
        for v in vars_a:
            if v and v[0] == fb[0]:
                return True, 0.90, f"Nickname initial match ('{fa}' -> '{v}' vs '{fb[0]}')"

    return False, 0.0, "Distinct first names"


def compute_pair_score(
    rec_a: dict[str, Any],
    rec_b: dict[str, Any],
) -> tuple[float, list[str]]:
    """Compute pairwise match confidence (0.0 to 1.0) and supporting reasons."""
    reasons: list[str] = []

    # ── 1. Conflicting Employee IDs (Hard Invariant Violation: Conf 0.0) ────────
    emp_a = str(rec_a.get("employee_id") or rec_a.get("employee_id_hint") or "").strip().lower()
    emp_b = str(rec_b.get("employee_id") or rec_b.get("employee_id_hint") or "").strip().lower()

    if emp_a and emp_b and emp_a != emp_b:
        return 0.0, [f"Refused: conflicting employee IDs ('{emp_a}' vs '{emp_b}')"]

    # ── 2. Deterministic Rule Links (Confidence 1.0) ───────────────────────────
    if emp_a and emp_b and emp_a == emp_b:
        return 1.0, ["Deterministic: exact employee ID match"]

    email_a = str(rec_a.get("email") or "").strip().lower()
    email_b = str(rec_b.get("email") or "").strip().lower()

    if email_a and email_b and email_a == email_b:
        return 1.0, ["Deterministic: exact corporate email match"]

    # ── 3. Username / Email Local-Part Normalization ──────────────────────────
    local_a = extract_email_local_part(email_a or rec_a.get("username") or rec_a.get("user_key") or "")
    local_b = extract_email_local_part(email_b or rec_b.get("username") or rec_b.get("user_key") or "")

    # Check for differing numerical suffixes (e.g. user1 vs user2)
    import re
    match_digits_a = re.search(r"(\d+)$", local_a)
    match_digits_b = re.search(r"(\d+)$", local_b)
    digits_a = match_digits_a.group(1) if match_digits_a else None
    digits_b = match_digits_b.group(1) if match_digits_b else None

    has_conflicting_digits = bool(digits_a and digits_b and digits_a != digits_b)
    if has_conflicting_digits:
        return 0.05, [f"Refused: conflicting account number suffixes ('{digits_a}' vs '{digits_b}')"]

    clean_a = strip_trailing_digits(local_a.replace(".", "").replace("_", "").replace("-", ""))
    clean_b = strip_trailing_digits(local_b.replace(".", "").replace("_", "").replace("-", ""))

    if clean_a and clean_b and clean_a == clean_b:
        reasons.append(f"Matching username / email local-part ('{clean_a}')")
        return 0.98, reasons

    # ── 4. Candidate Human Name Normalization ─────────────────────────────────
    name_a = normalize_name(rec_a.get("full_name") or rec_a.get("name") or "")
    if not name_a:
        name_a = normalize_name(derive_name_from_identifier(rec_a.get("username") or local_a))

    name_b = normalize_name(rec_b.get("full_name") or rec_b.get("name") or "")
    if not name_b:
        name_b = normalize_name(derive_name_from_identifier(rec_b.get("username") or local_b))

    tokens_a = tokenize_name(name_a)
    tokens_b = tokenize_name(name_b)
    init_a, sur_a = get_initials_and_surname(name_a)
    init_b, sur_b = get_initials_and_surname(name_b)

    first_a = tokens_a[0] if tokens_a else ""
    first_b = tokens_b[0] if tokens_b else ""

    # Check organizational context
    dept_a = str(rec_a.get("department") or "").strip().lower()
    dept_b = str(rec_b.get("department") or "").strip().lower()
    same_dept = bool(dept_a and dept_b and dept_a == dept_b)

    same_domain = False
    if email_a and email_b and "@" in email_a and "@" in email_b:
        same_domain = (email_a.split("@")[-1] == email_b.split("@")[-1])

    # ── 5. Username Convention Matching (flast / lastf) ───────────────────────
    # e.g., 'rdavis' or 'rdavis99' matching 'Robert Davis'
    if len(tokens_a) == 1 and sur_b:
        if clean_a in (f"{init_b}{sur_b}", f"{sur_b}{init_b}"):
            reasons.append(f"Username format '{clean_a}' matches initials & surname '{init_b} {sur_b}'")
            return 0.94, reasons
    if len(tokens_b) == 1 and sur_a:
        if clean_b in (f"{init_a}{sur_a}", f"{sur_a}{init_a}"):
            reasons.append(f"Username format '{clean_b}' matches initials & surname '{init_a} {sur_a}'")
            return 0.94, reasons

    # ── 6. Full Name & Surname Alignment ─────────────────────────────────────
    if sur_a and sur_b:
        sur_sim = jw.similarity(sur_a, sur_b)
        # Handle germanic 'ue' / 'u' or small typos
        sur_norm_a = sur_a.replace("ue", "u")
        sur_norm_b = sur_b.replace("ue", "u")
        same_surname = (sur_a == sur_b or sur_norm_a == sur_norm_b or sur_sim >= 0.92)

        if same_surname:
            is_first_match, first_score, first_reason = _evaluate_first_name_match(first_a, first_b)
            if is_first_match:
                conf = min(0.97, 0.90 + 0.05 * first_score)
                reasons.append(f"{first_reason} with matching surname '{sur_a}'")
                if same_dept:
                    conf = min(0.98, conf + 0.02)
                    reasons.append(f"Same department ('{dept_a}')")
                if same_domain:
                    conf = min(0.98, conf + 0.01)
                return round(conf, 2), reasons
            elif first_a and first_b and len(first_a) >= 3 and len(first_b) >= 3:
                # Explicitly distinct first names sharing same surname (e.g. John Smith vs Jane Smith)
                return 0.15, [f"Distinct first names ('{first_a}' vs '{first_b}') with matching surname '{sur_a}'"]


    # ── 7. Fuzzy Full Name Similarity ─────────────────────────────────────────
    if name_a and name_b:
        token_set = fuzz.token_set_ratio(name_a, name_b) / 100.0
        jw_name = jw.similarity(name_a, name_b)
        combined_name = max(token_set, jw_name)

        if combined_name >= 0.90:
            reasons.append(f"High name string similarity ({int(combined_name * 100)}%)")
            conf = 0.85 + 0.10 * (combined_name - 0.90) / 0.10
            if same_dept or same_domain:
                conf += 0.04
            return round(min(0.95, conf), 2), reasons
        elif combined_name >= 0.80:
            reasons.append(f"Moderate name similarity ({int(combined_name * 100)}%)")
            return round(0.70 + 0.15 * (combined_name - 0.80) / 0.10, 2), reasons

    # ── 8. Weak/No Match ──────────────────────────────────────────────────────
    return 0.05, reasons
