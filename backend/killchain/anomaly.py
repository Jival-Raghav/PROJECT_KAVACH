"""Per-entity anomaly scores from firewall behaviour.

Internal hosts, external IPs and users are scored separately, because their normal behaviour is
not comparable. Scores are context only: they never create incidents or change risk scores.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from killchain.models import Incident

LEAD_MIN_SCORE = 50.0
LEAD_CUTOFFS = {"external_ip": 80.0}  # over a million external IPs: 50 would list 112,000 of them
_MIN_PEERS = 10
_MAX_REASONS = 3
_MIN_DEVIATION = 2.0  # further reasons must be at least this many robust deviations out

_IP_FEATURES = {
    "events": "count(*)",
    "destinations": "count(DISTINCT dstip)",
    "destination_ports": "count(DISTINCT dstport)",
    "denied_events": "count(*) FILTER (WHERE action IN ('deny', 'blocked', 'dropped'))",
    "bytes_sent": "coalesce(sum(sentbyte), 0)",
    "ips_alerts": "count(*) FILTER (WHERE subtype = 'ips')",
    "virus_alerts": "count(*) FILTER (WHERE subtype = 'virus')",
    "failed_admin_logins": "count(*) FILTER (WHERE logdesc = 'Admin login failed')",
    "active_hours": "count(DISTINCT date_trunc('hour', ts))",
}
_USER_FEATURES = {
    "events": "count(*)",
    "source_ips": "count(DISTINCT srcip)",
    "source_countries": "count(DISTINCT srccountry)",
    "failed_admin_logins": "count(*) FILTER (WHERE logdesc = 'Admin login failed')",
    "admin_logins": "count(*) FILTER (WHERE logdesc = 'Admin login successful')",
    "config_changes": "count(*) FILTER (WHERE logdesc IN "
                      "('Attribute configured', 'Object attribute configured'))",
    "active_hours": "count(DISTINCT date_trunc('hour', ts))",
}
_LABELS = {
    "events": "events", "destinations": "destinations", "destination_ports": "destination ports",
    "denied_events": "denied events", "bytes_sent": "bytes sent", "ips_alerts": "IPS alerts",
    "virus_alerts": "virus alerts", "failed_admin_logins": "failed admin logins",
    "active_hours": "active hours", "source_ips": "source IPs",
    "source_countries": "source countries", "admin_logins": "admin logins",
    "config_changes": "configuration changes",
}


def _frame(con, column: str, features: dict[str, str]) -> pd.DataFrame:
    selected = ", ".join(f"{sql} AS {name}" for name, sql in features.items())
    return con.execute(f"""
        SELECT {column} AS entity, {selected} FROM events
        WHERE {column} IS NOT NULL AND {column} <> '' GROUP BY 1 ORDER BY 1""").fetchdf()


def _reasons(values: np.ndarray, deviations: np.ndarray, names: list[str],
             medians: np.ndarray) -> list[str]:
    """The behaviours furthest from this entity type's median, high or low, in plain words."""
    order = np.argsort(-np.abs(deviations))[:_MAX_REASONS]
    out = []
    for i in order:
        if out and abs(deviations[i]) < _MIN_DEVIATION:
            break
        value, median = float(values[i]), float(medians[i])
        ratio = (value + 1) / (median + 1)
        if ratio >= 2:
            how = f"{ratio:,.0f}× the peer median of {median:,.0f}"
        elif ratio <= 0.5:
            how = f"{1 / ratio:,.0f}× below the peer median of {median:,.0f}"
        else:
            side = "above" if value > median else "below"
            how = f"unusually far {side} the peer median of {median:,.0f}"
        out.append(f"{_LABELS[names[i]]}: {value:,.0f} ({how})")
    return out


def _score_group(df: pd.DataFrame, kind: str, min_score: float, wanted: set[str]) -> list[dict]:
    """Score one entity type; keep rows above `min_score` or named in `wanted`."""
    if len(df) < _MIN_PEERS:
        return []
    features = df.drop(columns="entity").astype(float)
    logged = np.log1p(features.to_numpy())
    model = IsolationForest(n_estimators=200, max_samples=min(256, len(df)), random_state=42)
    raw = -model.fit(logged).score_samples(logged)
    span = raw.max() - raw.min()
    scores = 100 * (raw - raw.min()) / span if span > 0 else np.zeros(len(raw))
    # Robust spread per feature, so a small move in a very tight feature still counts.
    center = np.median(logged, axis=0)
    spread = 1.4826 * np.median(np.abs(logged - center), axis=0)
    spread = np.where(spread > 0, spread, np.maximum(logged.std(axis=0), 1e-9))
    deviations = (logged - center) / spread
    names, values, medians = list(features.columns), features.to_numpy(), features.median().to_numpy()
    out = []
    for i in np.flatnonzero((scores > min_score) | df["entity"].isin(wanted).to_numpy()):
        out.append({"entity": str(df["entity"].iloc[i]), "kind": kind,
                    "score": round(float(scores[i]), 1),
                    "reasons": _reasons(values[i], deviations[i], names, medians)})
    return out


def score_entities(con, wanted: set[str] | None = None,
                   min_score: float = LEAD_MIN_SCORE,
                   internal_prefixes: tuple[str, ...] = ("10.",)) -> list[dict]:
    """Entities scoring above `min_score`, plus every entity named in `wanted`."""
    wanted = wanted or set()
    ips = _frame(con, "srcip", _IP_FEATURES)
    internal = ips["entity"].str.startswith(internal_prefixes)
    rows = (_score_group(ips[internal], "internal_host", min_score, wanted)
            + _score_group(ips[~internal], "external_ip", min_score, wanted)
            + _score_group(_frame(con, "user", _USER_FEATURES), "user", min_score, wanted))
    return sorted(rows, key=lambda r: (-r["score"], r["kind"], r["entity"]))


def incident_entities(inc: Incident) -> set[str]:
    return {v for role in ("src_ip", "dst_ip", "user") for v in inc.entities.get(role, [])}


def split_scores(scored: list[dict],
                 incidents: list[Incident]) -> tuple[list[dict], dict[int, list[dict]]]:
    """(leads: above their type's cutoff and in no incident, per-incident score context)."""
    by_entity = {r["entity"]: r for r in scored}
    in_incident: set[str] = set()
    context: dict[int, list[dict]] = {}
    for inc in incidents:
        names = incident_entities(inc)
        in_incident |= names
        rows = [by_entity[n] for n in names if n in by_entity]
        context[inc.incident_id] = sorted(rows, key=lambda r: (-r["score"], r["entity"]))
    leads = [r for r in scored
             if r["score"] > LEAD_CUTOFFS.get(r["kind"], LEAD_MIN_SCORE)
             and r["entity"] not in in_incident]
    return leads, context
