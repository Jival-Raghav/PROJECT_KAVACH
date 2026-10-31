"""backend/detect/features.py
Schema-Independent Feature Engineering for ISPAD v2.

Computes detection feature vectors strictly from canonical models:
- Baseline features: after_hours_ratio, weekend_ratio, sensitivity_ratio, distinct_systems, inactivity_days
- Advanced features: rolling history z-score, failed-login ratio, new-system-access rate,
  impossible travel & geo/IP novelty, burst/mass-access rate per hour, privileged-action ratio,
  unused-entitlement ratio, entitlement count vs peer median.
- Custom Unified Schema features (role 'feature' with cardinality caps).
- Graceful degradation: auto-skips missing features when source data is unavailable.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from core.models import (
    CanonicalAccount,
    CanonicalBundle,
    CanonicalEntitlement,
    CanonicalEvent,
    CanonicalIdentity,
)

# Approximate coordinate centroids for major geographical regions to compute travel speed
GEO_COORDINATES: dict[str, tuple[float, float]] = {
    "us": (37.0902, -95.7129),
    "usa": (37.0902, -95.7129),
    "united states": (37.0902, -95.7129),
    "new york": (40.7128, -74.0060),
    "california": (36.7783, -119.4179),
    "san francisco": (37.7749, -122.4194),
    "uk": (55.3781, -3.4360),
    "london": (51.5074, -0.1278),
    "de": (51.1657, 10.4515),
    "frankfurt": (50.1109, 8.6821),
    "germany": (51.1657, 10.4515),
    "in": (20.5937, 78.9629),
    "india": (20.5937, 78.9629),
    "mumbai": (19.0760, 72.8777),
    "bengaluru": (12.9716, 77.5946),
    "sg": (1.3521, 103.8198),
    "singapore": (1.3521, 103.8198),
    "jp": (36.2048, 138.2529),
    "tokyo": (35.6762, 139.6503),
    "japan": (36.2048, 138.2529),
    "au": (-25.2744, 133.7751),
    "sydney": (-33.8688, 151.2093),
    "australia": (-25.2744, 133.7751),
    "ru": (61.5240, 105.3188),
    "russia": (61.5240, 105.3188),
    "moscow": (55.7558, 37.6173),
    "cn": (35.8617, 104.1954),
    "china": (35.8617, 104.1954),
}

PRIVILEGED_ACTIONS = {
    "admin_operation",
    "sudo",
    "modify_policy",
    "grant_role",
    "delete_log",
    "clear_audit_stream",
    "create_user",
    "delete_user",
    "export_data",
    "modify_security_group",
    "iam_policy_put",
    "assume_role",
    "password_reset",
}


def haversine_km(coord1: tuple[float, float], coord2: tuple[float, float]) -> float:
    """Calculate distance in kilometers between two lat/lon coordinates."""
    lat1, lon1 = coord1
    lat2, lon2 = coord2
    r = 6371.0  # Earth radius in km

    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def parse_iso_dt(ts_val: Any) -> datetime | None:
    if not ts_val:
        return None
    s = str(ts_val).strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt[: len(s[:19])]).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        ts_float = float(s)
        if ts_float > 1e11:
            ts_float /= 1000.0
        return datetime.fromtimestamp(ts_float, tz=UTC)
    except Exception:
        return None


class FeatureExtractionResult:

    def __init__(
        self,
        user_ids: list[str],
        feature_names: list[str],
        matrix: np.ndarray,
        dataframe: pd.DataFrame,
        active_features: list[str],
        skipped_features: list[str],
        degradation_reasons: dict[str, str],
    ):
        self.user_ids = user_ids
        self.feature_names = feature_names
        self.matrix = matrix
        self.dataframe = dataframe
        self.active_features = active_features
        self.skipped_features = skipped_features
        self.degradation_reasons = degradation_reasons

    @property
    def skipped_reasons(self) -> dict[str, str]:
        return self.degradation_reasons


def extract_canonical_features(
    bundle: CanonicalBundle,
    peer_medians: dict[str, float] | None = None,
    reference_time: datetime | None = None,
    custom_feature_defs: list[dict[str, Any]] | None = None,
) -> FeatureExtractionResult:
    """Extract full feature matrix from a CanonicalBundle across all users.

    Gracefully skips features whose required fields/tables are missing.
    """
    identities: list[CanonicalIdentity] = bundle.identities
    accounts: list[CanonicalAccount] = bundle.accounts
    events: list[CanonicalEvent] = bundle.events
    entitlements: list[CanonicalEntitlement] = bundle.entitlements

    # Determine unique user anchors
    # Primary user key is identity_id if identities exist, else distinct account usernames
    user_keys: list[str] = []
    user_identity_map: dict[str, CanonicalIdentity] = {}
    user_accounts_map: dict[str, list[CanonicalAccount]] = defaultdict(list)
    user_events_map: dict[str, list[CanonicalEvent]] = defaultdict(list)
    user_entitlements_map: dict[str, list[CanonicalEntitlement]] = defaultdict(list)

    if identities:
        for ident in identities:
            uid = ident.identity_id
            user_keys.append(uid)
            user_identity_map[uid] = ident

        # Map accounts to identities
        for acc in accounts:
            matched_uid = None
            if acc.extra.get("identity_id") in user_identity_map:
                matched_uid = acc.extra.get("identity_id")
            elif acc.account_id in user_identity_map:
                matched_uid = acc.account_id
            elif acc.employee_id_hint:
                for ident in identities:
                    if ident.employee_id and ident.employee_id.lower() == acc.employee_id_hint.lower():
                        matched_uid = ident.identity_id
                        break
            if not matched_uid:
                matched_uid = acc.username
            user_accounts_map[matched_uid].append(acc)
    else:
        # No identities table: anchor on accounts or event user_keys
        if accounts:
            for acc in accounts:
                uid = acc.username or acc.account_id
                if uid not in user_keys:
                    user_keys.append(uid)
                user_accounts_map[uid].append(acc)
        else:
            # Fallback purely to distinct event user_keys
            for ev in events:
                uid = ev.user_key
                if uid not in user_keys:
                    user_keys.append(uid)

    # Index events
    all_event_times: list[datetime] = []
    has_event_timestamps = False
    has_geo_or_ip = False
    has_sensitivity = False
    has_success_field = False

    for ev in events:
        user_events_map[ev.user_key].append(ev)
        dt = parse_iso_dt(ev.timestamp)
        if dt:
            has_event_timestamps = True
            all_event_times.append(dt)
        if ev.geo or ev.source_ip:
            has_geo_or_ip = True
        if ev.resource_sensitivity in ("high", "crown", "medium"):
            has_sensitivity = True
        if ev.success is not None:
            has_success_field = True

    # Index entitlements
    has_entitlements = len(entitlements) > 0
    for ent in entitlements:
        user_entitlements_map[ent.account_id].append(ent)

    # Establish global reference time
    if reference_time is None:
        if all_event_times:
            reference_time = max(all_event_times)
        else:
            reference_time = datetime.now(UTC)

    # Feature tracking
    active_features: list[str] = []
    skipped_features: list[str] = []
    degradation_reasons: dict[str, str] = {}

    def register_feature(name: str, condition: bool, reason_if_skipped: str) -> bool:
        if condition:
            active_features.append(name)
            return True
        else:
            skipped_features.append(name)
            degradation_reasons[name] = reason_if_skipped
            return False

    # Check data availability conditions
    has_events = len(events) > 0
    can_after_hours = register_feature("after_hours_ratio", has_event_timestamps, "Missing event timestamps")
    can_weekend = register_feature("weekend_ratio", has_event_timestamps, "Missing event timestamps")
    can_sensitivity = register_feature("sensitivity_ratio", has_events and has_sensitivity, "No resource sensitivity tags")
    can_distinct_systems = register_feature("distinct_systems", has_events or len(accounts) > 0, "No systems or events data")
    can_inactivity_days = register_feature("inactivity_days", has_event_timestamps or any(a.last_login for a in accounts), "No login timestamps")
    can_history_zscore = register_feature("history_zscore", has_event_timestamps, "Requires event timestamps for rolling window")
    can_failed_login = register_feature("failed_login_ratio", has_events and has_success_field, "Event success/failure status unmapped")
    can_new_systems = register_feature("new_system_access_rate", has_events, "No event streams to evaluate system discovery")
    can_impossible_travel = register_feature("impossible_travel_flag", has_geo_or_ip, "No IP or geographic location coordinates")
    can_burst = register_feature("burst_access_count", has_event_timestamps, "Requires event timestamps for hourly burst analysis")
    can_privileged = register_feature("privileged_action_ratio", has_events, "No events to measure privileged actions")
    can_unused_ent = register_feature("unused_entitlement_ratio", has_entitlements and has_events, "Requires both entitlements and events")
    can_peer_median = register_feature("entitlement_vs_peer_median", has_entitlements, "Entitlements table unmapped")

    # Custom fields from Unified Schema
    custom_features: list[str] = []
    if custom_feature_defs:
        for cdef in custom_feature_defs:
            fname = f"custom_{cdef['name']}"
            active_features.append(fname)
            custom_features.append(fname)

    # Extract feature values per user
    feature_rows: list[dict[str, float]] = []

    for uid in user_keys:
        u_events = user_events_map.get(uid, [])
        u_accounts = user_accounts_map.get(uid, [])

        # Gather user's accounts' events if not found directly
        if not u_events and u_accounts:
            for acc in u_accounts:
                u_events.extend(user_events_map.get(acc.username, []))

        # Gather user's entitlements
        u_entitlements: list[CanonicalEntitlement] = []
        for acc in u_accounts:
            u_entitlements.extend(user_entitlements_map.get(acc.account_id, []))
            u_entitlements.extend(user_entitlements_map.get(acc.username, []))

        row: dict[str, float] = {}

        # ── 1. After Hours Ratio (outside 08:00 - 18:00 UTC/local) ────────────
        if can_after_hours:
            if u_events:
                after_count = sum(
                    1 for e in u_events
                    if (dt := parse_iso_dt(e.timestamp)) and (dt.hour < 8 or dt.hour >= 18)
                )
                row["after_hours_ratio"] = round(after_count / len(u_events), 4)
            else:
                row["after_hours_ratio"] = 0.0

        # ── 2. Weekend Ratio (Saturday=5, Sunday=6) ───────────────────────────
        if can_weekend:
            if u_events:
                weekend_count = sum(
                    1 for e in u_events
                    if (dt := parse_iso_dt(e.timestamp)) and dt.weekday() >= 5
                )
                row["weekend_ratio"] = round(weekend_count / len(u_events), 4)
            else:
                row["weekend_ratio"] = 0.0

        # ── 3. Sensitivity Ratio (high or crown jewel) ────────────────────────
        if can_sensitivity:
            if u_events:
                high_count = sum(
                    1 for e in u_events
                    if str(e.resource_sensitivity).lower() in ("high", "crown")
                )
                row["sensitivity_ratio"] = round(high_count / len(u_events), 4)
            else:
                row["sensitivity_ratio"] = 0.0

        # ── 4. Distinct Systems ───────────────────────────────────────────────
        if can_distinct_systems:
            ev_systems = {e.system for e in u_events if e.system}
            acc_systems = {a.system for a in u_accounts if a.system}
            total_systems = len(ev_systems | acc_systems)
            row["distinct_systems"] = float(total_systems)

        # ── 5. Inactivity Days ────────────────────────────────────────────────
        if can_inactivity_days:
            latest_time: datetime | None = None
            for e in u_events:
                dt = parse_iso_dt(e.timestamp)
                if dt and (latest_time is None or dt > latest_time):
                    latest_time = dt
            for a in u_accounts:
                dt = parse_iso_dt(a.last_login)
                if dt and (latest_time is None or dt > latest_time):
                    latest_time = dt

            if latest_time and reference_time:
                delta_days = (reference_time - latest_time).total_seconds() / 86400.0
                row["inactivity_days"] = max(0.0, float(delta_days))
            else:
                row["inactivity_days"] = 0.0

        # ── 6. Rolling History Z-Score (vs own 30d baseline) ───────────────────
        if can_history_zscore:
            if u_events and len(u_events) >= 5:
                # Bin events into days
                day_counts: dict[str, int] = defaultdict(int)
                for e in u_events:
                    dt = parse_iso_dt(e.timestamp)
                    if dt:
                        day_counts[dt.strftime("%Y-%m-%d")] += 1

                counts = list(day_counts.values())
                if len(counts) >= 2:
                    mean_c = np.mean(counts)
                    std_c = np.std(counts)
                    latest_day = max(counts)
                    z = (latest_day - mean_c) / (std_c + 1e-4) if std_c > 0 else 0.0
                    row["history_zscore"] = round(float(np.clip(z, -3.0, 5.0)), 4)
                else:
                    row["history_zscore"] = 0.0
            else:
                row["history_zscore"] = 0.0

        # ── 7. Failed Login Ratio ─────────────────────────────────────────────
        if can_failed_login:
            if u_events:
                login_events = [
                    e for e in u_events
                    if "login" in str(e.action).lower() or "auth" in str(e.action).lower()
                ]
                if login_events:
                    fail_count = sum(1 for e in login_events if not e.success)
                    row["failed_login_ratio"] = round(fail_count / len(login_events), 4)
                else:
                    row["failed_login_ratio"] = 0.0
            else:
                row["failed_login_ratio"] = 0.0

        # ── 8. New System Access Rate ─────────────────────────────────────────
        if can_new_systems:
            if len(u_events) > 5:
                # First half baseline vs second half new systems
                sorted_events = sorted(
                    u_events, key=lambda e: parse_iso_dt(e.timestamp) or datetime.min.replace(tzinfo=UTC)
                )
                split_idx = len(sorted_events) // 2
                baseline_systems = {e.system for e in sorted_events[:split_idx] if e.system}
                recent_events = sorted_events[split_idx:]
                new_touches = sum(1 for e in recent_events if e.system and e.system not in baseline_systems)
                row["new_system_access_rate"] = round(new_touches / max(1, len(recent_events)), 4)
            else:
                row["new_system_access_rate"] = 0.0

        # ── 9. Impossible Travel & Geo Novelty Flag ───────────────────────────
        if can_impossible_travel:
            has_impossible_jump = False
            geo_events = [
                (parse_iso_dt(e.timestamp), (e.geo or "").strip().lower(), (e.source_ip or "").strip())
                for e in u_events
                if parse_iso_dt(e.timestamp) and (e.geo or e.source_ip)
            ]
            geo_events.sort(key=lambda x: x[0])

            for i in range(len(geo_events) - 1):
                t1, geo1, ip1 = geo_events[i]
                t2, geo2, ip2 = geo_events[i + 1]
                time_delta_h = (t2 - t1).total_seconds() / 3600.0

                g1 = geo1 or (ip1.lower() if ip1.lower() in GEO_COORDINATES else "")
                g2 = geo2 or (ip2.lower() if ip2.lower() in GEO_COORDINATES else "")

                if time_delta_h < 6.0 and g1 and g2 and g1 != g2:
                    c1 = GEO_COORDINATES.get(g1)
                    c2 = GEO_COORDINATES.get(g2)
                    if c1 and c2:
                        dist_km = haversine_km(c1, c2)
                        speed = dist_km / max(0.05, time_delta_h)
                        if speed > 800.0:  # Exceeds commercial flight speed
                            has_impossible_jump = True
                            break
                    else:
                        # Different named countries/regions within < 1 hour
                        if time_delta_h < 1.0:
                            has_impossible_jump = True
                            break

                # Subnet hopping within < 2 minutes
                if time_delta_h < (2.0 / 60.0) and ip1 and ip2 and ip1 != ip2:
                    sub1 = ".".join(ip1.split(".")[:2]) if "." in ip1 else ip1
                    sub2 = ".".join(ip2.split(".")[:2]) if "." in ip2 else ip2
                    if sub1 != sub2:
                        has_impossible_jump = True
                        break

            row["impossible_travel_flag"] = 1.0 if has_impossible_jump else 0.0

        # ── 10. Burst Access Count (Max events in 1 rolling hour) ─────────────
        if can_burst:
            if u_events:
                dts = sorted(
                    [dt for e in u_events if (dt := parse_iso_dt(e.timestamp))]
                )
                max_in_hour = 1
                for i in range(len(dts)):
                    window_end = dts[i] + timedelta(hours=1)
                    # Count events up to window_end
                    cnt = sum(1 for t in dts[i:] if t <= window_end)
                    if cnt > max_in_hour:
                        max_in_hour = cnt
                row["burst_access_count"] = float(max_in_hour)
            else:
                row["burst_access_count"] = 0.0

        # ── 11. Privileged Action Ratio ───────────────────────────────────────
        if can_privileged:
            if u_events:
                priv_cnt = sum(1 for e in u_events if e.action and e.action.lower() in PRIVILEGED_ACTIONS)
                row["privileged_action_ratio"] = round(priv_cnt / len(u_events), 4)
            else:
                row["privileged_action_ratio"] = 0.0

        # ── 12. Unused Entitlement Ratio ──────────────────────────────────────
        if can_unused_ent:
            if u_entitlements:
                used_actions = {e.action.lower() for e in u_events if e.action}
                used_resources = {e.resource.lower() for e in u_events if e.resource}
                active_ent_count = 0
                for ent in u_entitlements:
                    ename = ent.entitlement.lower()
                    if ename in used_actions or ename in used_resources:
                        active_ent_count += 1
                unused_ratio = 1.0 - (active_ent_count / len(u_entitlements))
                row["unused_entitlement_ratio"] = round(max(0.0, unused_ratio), 4)
            else:
                row["unused_entitlement_ratio"] = 0.0

        # ── 13. Entitlement Count vs Peer Median ──────────────────────────────
        if can_peer_median:
            user_ent_count = float(len(u_entitlements))
            peer_med = (peer_medians or {}).get(uid, 5.0)
            diff = user_ent_count - peer_med
            row["entitlement_vs_peer_median"] = round(diff, 2)

        # ── 14. Custom Unified Schema Features ────────────────────────────────
        for cf in custom_features:
            val = 0.0
            ident = user_identity_map.get(uid)
            if ident and cf.replace("custom_", "") in ident.extra:
                val = float(ident.extra.get(cf.replace("custom_", ""), 0.0) or 0.0)
            row[cf] = val

        feature_rows.append(row)

    # Build DataFrame
    df = pd.DataFrame(feature_rows, index=user_keys)
    # Ensure all active features are columns in fixed order
    for col in active_features:
        if col not in df.columns:
            df[col] = 0.0

    df = df[active_features].fillna(0.0)
    matrix = df.to_numpy(dtype=float)

    return FeatureExtractionResult(
        user_ids=user_keys,
        feature_names=active_features,
        matrix=matrix,
        dataframe=df,
        active_features=active_features,
        skipped_features=skipped_features,
        degradation_reasons=degradation_reasons,
    )
