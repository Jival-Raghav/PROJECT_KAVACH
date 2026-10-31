"""backend/resolve/classify.py
Account Classification Engine for ISPAD v2.

Categorizes accounts into:
- leaver_active (Critical): Terminated HR identity with active account or post-termination activity.
- orphaned (High): Active account with no matching HR identity.
- shared (High): Generic role account or concurrent multi-IP/geo access.
- dormant (Medium): Active account with no activity exceeding DORMANT_DAYS (default 90).
- service (Medium/Low): Service/daemon/pipeline accounts, flagging missing human owners.
- human (Low): Standard active employee account.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from config import get_settings
from core.models import (
    AccountClassification,
    CanonicalAccount,
    CanonicalEvent,
    CanonicalIdentity,
    GoldenIdentity,
)

SERVICE_PATTERN = re.compile(
    r"(?i)(^(svc|bot|batch|sys|app[-_]|daemon|service|api[-_]|pipeline|worker|agent|runner)|[-_]svc$|service$|_service)",
)

SHARED_PATTERN = re.compile(
    r"(?i)^(admin|administrator|root|ops|support|test|guest|deploy|shared|security|infra|it-admin|superuser)$",
)


def parse_timestamp(ts_val: Any) -> datetime | None:
    if not ts_val:
        return None
    s = str(ts_val).strip()
    if not s:
        return None
    # Try ISO formats
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt[: len(s[:19])]).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        # Check if float/epoch timestamp
        ts_float = float(s)
        if ts_float > 1e11:  # ms
            ts_float /= 1000.0
        return datetime.fromtimestamp(ts_float, tz=UTC)
    except Exception:
        return None


def classify_accounts(
    accounts: list[CanonicalAccount],
    identities: list[CanonicalIdentity],
    golden_identities: list[GoldenIdentity],
    events: list[CanonicalEvent] | None = None,
    reference_time: datetime | None = None,
) -> list[AccountClassification]:
    """Evaluate and classify all accounts across security risk dimensions.

    Parameters:
    - accounts: list of CanonicalAccount
    - identities: list of HR CanonicalIdentity
    - golden_identities: list of GoldenIdentity output from clustering
    - events: optional list of CanonicalEvent to inspect login recency and IP/geo sprawl
    - reference_time: optional reference timestamp for dormancy calculation (defaults to max event time or UTC now)
    """
    cfg = get_settings()
    dormant_threshold_days = getattr(cfg, "DORMANT_DAYS", 90)

    # Index HR identities
    hr_by_id: dict[str, CanonicalIdentity] = {i.identity_id: i for i in identities}
    hr_by_emp: dict[str, CanonicalIdentity] = {
        i.employee_id.strip().lower(): i
        for i in identities
        if i.employee_id
    }

    # Map account_id -> GoldenIdentity
    golden_by_acc: dict[str, GoldenIdentity] = {}
    for gid in golden_identities:
        for acc_id in gid.linked_account_ids:
            golden_by_acc[acc_id] = gid

    # Index events by user_key / account username
    events_by_user: dict[str, list[CanonicalEvent]] = {}
    all_event_times: list[datetime] = []

    if events:
        for ev in events:
            key = str(ev.user_key).strip().lower()
            events_by_user.setdefault(key, []).append(ev)
            dt = parse_timestamp(ev.timestamp)
            if dt:
                all_event_times.append(dt)

    # Determine reference benchmark time
    if reference_time is None:
        if all_event_times:
            reference_time = max(all_event_times)
        else:
            reference_time = datetime.now(UTC)

    classifications: list[AccountClassification] = []

    for acc in accounts:
        reasons: list[str] = []
        acc_key = str(acc.username).strip().lower()
        acc_events = events_by_user.get(acc_key, [])
        if not acc_events and acc.account_id:
            acc_events = events_by_user.get(str(acc.account_id).strip().lower(), [])

        # Find linked HR identity if any
        linked_hr: CanonicalIdentity | None = None
        golden = golden_by_acc.get(acc.account_id)

        if golden and golden.extra.get("hr_backed"):
            linked_hr = hr_by_id.get(golden.identity_id)

        if not linked_hr and acc.employee_id_hint:
            linked_hr = hr_by_emp.get(acc.employee_id_hint.strip().lower())

        is_disabled = (acc.status or "").strip().lower() in ("disabled", "inactive", "suspended", "deprovisioned")

        # ── 1. Calculate Activity Recency and Inactivity Days ─────────────────
        latest_activity: datetime | None = parse_timestamp(acc.last_login)
        for ev in acc_events:
            ev_dt = parse_timestamp(ev.timestamp)
            if ev_dt:
                if latest_activity is None or ev_dt > latest_activity:
                    latest_activity = ev_dt

        inactivity_days: int | None = None
        if latest_activity and reference_time:
            delta = (reference_time - latest_activity).total_seconds() / 86400.0
            inactivity_days = max(0, int(delta))

        # ── 2. Check Service Account ─────────────────────────────────────────
        is_service_name = bool(SERVICE_PATTERN.search(acc.username))
        is_service_type = (acc.account_type or "").strip().lower() == "service"
        is_service = is_service_name or is_service_type

        # ── 3. Check Shared Account ──────────────────────────────────────────
        is_shared_name = bool(SHARED_PATTERN.search(acc.username))
        is_shared_type = (acc.account_type or "").strip().lower() == "shared"

        # Check multi-geo or multi-IP concurrency in events
        distinct_ips = {ev.source_ip for ev in acc_events if ev.source_ip}
        distinct_geos = {ev.geo for ev in acc_events if ev.geo}
        is_shared_behavior = len(distinct_ips) >= 3 or len(distinct_geos) >= 2

        is_shared = is_shared_name or is_shared_type or is_shared_behavior

        # ── 4. Security Rule Checks in Priority Order ─────────────────────────

        # Priority 1: LEAVER_ACTIVE (Critical)
        is_leaver = False
        if linked_hr:
            status_term = (linked_hr.employment_status or "").strip().lower() in ("terminated", "resigned", "departed")
            term_date = parse_timestamp(linked_hr.termination_date)

            has_post_term_login = False
            if term_date:
                if latest_activity and latest_activity > term_date:
                    has_post_term_login = True
                for ev in acc_events:
                    ev_dt = parse_timestamp(ev.timestamp)
                    if ev_dt and ev_dt > term_date:
                        has_post_term_login = True
                        break

            if status_term or (term_date and term_date < reference_time):
                if not is_disabled or has_post_term_login:
                    is_leaver = True
                    reasons.append(
                        f"HR status is terminated ({linked_hr.termination_date or 'no date'}) "
                        f"but account is {acc.status or 'active'}"
                    )
                    if has_post_term_login:
                        reasons.append("Detected login events occurring after formal termination date")

        if is_leaver:
            classifications.append(
                AccountClassification(
                    account_id=acc.account_id,
                    system=acc.system,
                    username=acc.username,
                    classification="leaver_active",
                    reasons=reasons,
                    inactivity_days=inactivity_days,
                    owner=linked_hr.full_name if linked_hr else None,
                    risk_level="critical",
                )
            )
            continue

        # Priority 2: ORPHANED (High)
        # Active account with no HR identity match (and not an explicitly configured service account)
        if not linked_hr and not is_disabled and not is_service:
            reasons.append("No matching HR identity or employee record found")
            if acc.employee_id_hint:
                reasons.append(f"Unresolvable employee_id_hint '{acc.employee_id_hint}'")
            if acc.privilege_level in ("admin", "elevated"):
                reasons.append(f"Orphan account holds elevated '{acc.privilege_level}' privileges")

            classifications.append(
                AccountClassification(
                    account_id=acc.account_id,
                    system=acc.system,
                    username=acc.username,
                    classification="orphaned",
                    reasons=reasons,
                    inactivity_days=inactivity_days,
                    owner=None,
                    risk_level="high" if acc.privilege_level in ("admin", "elevated") else "medium",
                )
            )
            continue

        # Priority 3: SHARED (High)
        if is_shared and not is_disabled:
            if is_shared_name:
                reasons.append(f"Generic unassigned account name ('{acc.username}')")
            if is_shared_behavior:
                reasons.append(
                    f"Sprawling concurrent access: {len(distinct_ips)} distinct IPs, "
                    f"{len(distinct_geos)} distinct geographies"
                )
            if is_shared_type:
                reasons.append("Account type explicitly tagged as 'shared'")

            classifications.append(
                AccountClassification(
                    account_id=acc.account_id,
                    system=acc.system,
                    username=acc.username,
                    classification="shared",
                    reasons=reasons,
                    inactivity_days=inactivity_days,
                    owner=linked_hr.full_name if linked_hr else None,
                    risk_level="high" if is_shared_behavior or acc.privilege_level in ("admin", "elevated") else "medium",
                )
            )
            continue

        # Priority 4: DORMANT (Medium)
        if (
            not is_disabled
            and inactivity_days is not None
            and inactivity_days >= dormant_threshold_days
        ):
            reasons.append(
                f"No activity for {inactivity_days} days (threshold {dormant_threshold_days} days)"
            )
            if acc.privilege_level in ("admin", "elevated"):
                reasons.append(f"Dormant account retains '{acc.privilege_level}' privilege level")

            classifications.append(
                AccountClassification(
                    account_id=acc.account_id,
                    system=acc.system,
                    username=acc.username,
                    classification="dormant",
                    reasons=reasons,
                    inactivity_days=inactivity_days,
                    owner=linked_hr.full_name if linked_hr else None,
                    risk_level="high" if acc.privilege_level in ("admin", "elevated") else "medium",
                )
            )
            continue

        # Priority 5: SERVICE (Medium if unowned, Low if owned)
        if is_service:
            owner = linked_hr.full_name if linked_hr else acc.extra.get("owner")
            if not owner:
                reasons.append("Service account lacks a designated human owner / sponsor")
                risk = "medium"
            else:
                reasons.append(f"Service account assigned to owner '{owner}'")
                risk = "low"

            classifications.append(
                AccountClassification(
                    account_id=acc.account_id,
                    system=acc.system,
                    username=acc.username,
                    classification="service",
                    reasons=reasons,
                    inactivity_days=inactivity_days,
                    owner=owner,
                    risk_level=risk,
                )
            )
            continue

        # Priority 6: Standard HUMAN account
        reasons.append("Active human account with resolved HR identity")
        classifications.append(
            AccountClassification(
                account_id=acc.account_id,
                system=acc.system,
                username=acc.username,
                classification="human",
                reasons=reasons,
                inactivity_days=inactivity_days,
                owner=linked_hr.full_name if linked_hr else None,
                risk_level="low",
            )
        )

    return classifications
