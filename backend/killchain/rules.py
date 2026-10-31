"""Config-driven detection rules (FR-2, B-4).

Rules live in YAML (`config/detection_rules/*.yaml`) and compile to DuckDB SQL over the
`events` view. Four kinds:

* match            – every matching event; grouped into gap-based sessions per `group_by`.
* threshold        – sessions with >= min_count events (and optional distinct-count floor).
* rare_for_entity  – events whose `value` is rare (< max_share) in the `key`'s baseline events.
* sequence         – `then_where` events preceded by >= min_count `where` events sharing
                     `join_on` within `then_within_minutes`.

Filters are a raw SQL `where` predicate and/or a Sigma-style `selection` map
(`field`, `field|contains`, `field|startswith`, `field|endswith`, `field|re`, `field|gte`,
`field|lte`; a list value means IN). Selection values are bound as parameters.
"""
from __future__ import annotations

import hashlib
import re
from datetime import UTC
from pathlib import Path
from typing import Any, Literal

import pyarrow as pa
import yaml
from pydantic import BaseModel, Field, field_validator

from killchain.mitre import label
from killchain.models import Detection, Severity

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_BLOCKED = ("deny", "blocked", "dropped")
_MAX_ENTITY_VALUES = 50
_SAMPLE_LINES = 50


class DistinctSpec(BaseModel):
    field: str
    min: int


class Rule(BaseModel):
    id: str
    title: str
    technique: str
    severity: Severity
    kind: Literal["match", "threshold", "rare_for_entity", "sequence"]
    where: str = "TRUE"
    selection: dict[str, Any] = Field(default_factory=dict)
    group_by: list[str] = Field(default_factory=list)
    window_minutes: float | None = None
    min_count: int = 1
    distinct: DistinctSpec | None = None
    entities: dict[str, str] = Field(default_factory=dict)
    # rare_for_entity
    baseline_where: str | None = None
    key: str | None = None
    value: str | None = None
    max_share: float = 0.01
    # sequence
    then_where: str | None = None
    join_on: str | None = None
    then_within_minutes: float = 60
    description: str = ""

    @field_validator("technique")
    @classmethod
    def _known_technique(cls, v: str) -> str:
        try:
            label(v)
        except KeyError as exc:
            raise ValueError(f"unknown ATT&CK technique {v!r}") from exc
        return v


def load_rules(rules_dir: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(Path(rules_dir).glob("*.y*ml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in doc.get("rules", []):
            rules.append(Rule(**raw))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    for r in rules:
        if r.kind == "rare_for_entity" and not (r.baseline_where and r.key and r.value):
            raise ValueError(f"{r.id}: rare_for_entity needs baseline_where, key and value")
        if r.kind == "sequence" and not (r.then_where and r.join_on):
            raise ValueError(f"{r.id}: sequence needs then_where and join_on")
    return rules


# ── SQL compilation ──────────────────────────────────────────────────────────

def _selection_sql(selection: dict[str, Any]) -> tuple[str, list]:
    parts, params = [], []
    for raw_key, value in selection.items():
        field, _, mod = raw_key.partition("|")
        if not _IDENT.match(field):
            raise ValueError(f"bad selection field {field!r}")
        if isinstance(value, list):
            parts.append(f"{field} IN ({', '.join('?' for _ in value)})")
            params.extend(value)
            continue
        op = {"": "{f} = ?", "contains": "contains({f}, ?)", "startswith": "starts_with({f}, ?)",
              "endswith": "ends_with({f}, ?)", "re": "regexp_matches({f}, ?)",
              "gte": "{f} >= ?", "lte": "{f} <= ?"}.get(mod)
        if op is None:
            raise ValueError(f"unknown selection modifier {mod!r}")
        parts.append(op.format(f=field))
        params.append(value)
    return (" AND ".join(parts) or "TRUE"), params


def _filter(rule: Rule) -> tuple[str, list]:
    sel, params = _selection_sql(rule.selection)
    return f"({rule.where}) AND ({sel})", params


def _matched_cte(rule: Rule) -> tuple[str, list]:
    """SQL for CTE `m`: the events this rule considers, before sessionising."""
    cond, params = _filter(rule)
    if rule.kind in ("match", "threshold"):
        return f"SELECT * FROM events WHERE {cond}", params
    if rule.kind == "rare_for_entity":
        k, v = rule.key, rule.value
        sql = f"""
          SELECT e.* FROM (SELECT * FROM events WHERE {cond}) e
          LEFT JOIN (SELECT {k} AS bk, {v} AS bv, count(*) AS c FROM events
                     WHERE {rule.baseline_where} GROUP BY ALL) b
                 ON b.bk = e.{k} AND b.bv = e.{v}
          LEFT JOIN (SELECT {k} AS tk, count(*) AS t FROM events
                     WHERE {rule.baseline_where} GROUP BY ALL) tot
                 ON tot.tk = e.{k}
          WHERE tot.t IS NULL OR coalesce(b.c, 0) < {float(rule.max_share)} * tot.t"""
        return sql, params
    # sequence
    j = rule.join_on
    win = float(rule.then_within_minutes)
    sql = f"""
      SELECT * FROM events WHERE line_no IN (
        WITH f AS (SELECT line_no, ts, {j} AS jk FROM events WHERE {cond}),
             t AS (SELECT line_no, ts, {j} AS jk FROM events WHERE {rule.then_where}),
             hits AS (SELECT t.line_no AS tl, f.line_no AS fl FROM t JOIN f
                        ON f.jk = t.jk AND f.ts <= t.ts
                       AND f.ts >= t.ts - to_microseconds(CAST({win} * 60000000 AS BIGINT))),
             q AS (SELECT tl FROM hits GROUP BY tl HAVING count(*) >= {int(rule.min_count)})
        SELECT tl FROM q UNION SELECT fl FROM hits WHERE tl IN (SELECT tl FROM q))"""
    return sql, params


def compile_rule(rule: Rule) -> tuple[str, list]:
    """Full SQL returning one row per detection (session)."""
    m_sql, params = _matched_cte(rule)
    group = rule.group_by or ([rule.key, rule.value] if rule.kind == "rare_for_entity"
                              else [rule.join_on] if rule.kind == "sequence" else [])
    gexprs = group or ["'all'"]
    gcols = [f"g{i}" for i in range(len(gexprs))]
    window = rule.window_minutes
    if window is None:
        window = rule.then_within_minutes if rule.kind == "sequence" else 10**7
    window_us = int(float(window) * 60_000_000)
    min_count = rule.min_count if rule.kind in ("match", "threshold") else 1
    dfield = rule.distinct.field if rule.distinct else "line_no"
    dmin = rule.distinct.min if rule.distinct else 0
    ent_sel = "".join(f", {expr} AS \"e_{role}\"" for role, expr in rule.entities.items())
    ent_agg = "".join(
        f", list(DISTINCT \"e_{role}\") FILTER (WHERE \"e_{role}\" IS NOT NULL AND "
        f"CAST(\"e_{role}\" AS VARCHAR) <> '') AS \"ent_{role}\""
        for role in rule.entities)
    part = ", ".join(gcols)
    blocked = ", ".join(f"'{a}'" for a in _BLOCKED)
    sql = f"""
    WITH m AS ({m_sql}),
    g AS (SELECT *, {', '.join(f'{e} AS {c}' for e, c in zip(gexprs, gcols))}{ent_sel},
                 ({dfield}) AS dval FROM m),
    s AS (SELECT *, CASE WHEN lag(ts) OVER w IS NULL
                          OR epoch_us(ts) - epoch_us(lag(ts) OVER w) > {window_us}
                         THEN 1 ELSE 0 END AS brk
          FROM g WINDOW w AS (PARTITION BY {part} ORDER BY ts, line_no)),
    t AS (SELECT *, sum(brk) OVER (PARTITION BY {part} ORDER BY ts, line_no
                                   ROWS UNBOUNDED PRECEDING) AS sess FROM s)
    SELECT {part}, sess, count(*) AS n, count(DISTINCT dval) AS d,
           min(ts) AS first_seen, max(ts) AS last_seen,
           list(line_no ORDER BY ts, line_no) AS lines,
           count(*) FILTER (WHERE action IN ({blocked})) AS n_blocked{ent_agg}
    FROM t GROUP BY {part}, sess
    HAVING count(*) >= {int(min_count)} AND count(DISTINCT dval) >= {int(dmin)}
    ORDER BY first_seen, {part}"""
    return sql, params


# ── Execution ────────────────────────────────────────────────────────────────

def _detection(rule: Rule, row: dict) -> Detection:
    gvals = [str(row[k]) for k in sorted(k for k in row if re.fullmatch(r"g\d+", k))]
    first, last = row["first_seen"], row["last_seen"]
    if first.tzinfo is None:
        first, last = first.replace(tzinfo=UTC), last.replace(tzinfo=UTC)
    digest = hashlib.sha1(f"{rule.id}|{'|'.join(gvals)}|{first.isoformat()}".encode()).hexdigest()
    n, nb = int(row["n"]), int(row["n_blocked"])
    outcome = "blocked" if nb == n else "allowed" if nb == 0 else "mixed"
    entities = {role: [str(v) for v in (row.get(f"ent_{role}") or [])][:_MAX_ENTITY_VALUES]
                for role in rule.entities}
    who = ", ".join(v for v in gvals if v != "all")
    extra = f", {row['d']} distinct {rule.distinct.field}" if rule.distinct else ""
    return Detection(
        detection_id=f"{rule.id}:{digest[:10]}", rule_id=rule.id, title=rule.title,
        technique=label(rule.technique), severity=rule.severity, first_seen=first,
        last_seen=last, event_count=n, sample_line_nos=list(row["lines"][:_SAMPLE_LINES]),
        entities={k: v for k, v in entities.items() if v}, outcome=outcome,
        summary=f"{rule.title} ({who}): {n} events{extra}",
    )


def run_rules(con, rules: list[Rule]) -> list[Detection]:
    """Run every rule; also (re)creates table `detection_events(detection_id, line_no)`."""
    detections: list[Detection] = []
    det_ids: list[str] = []
    line_nos: list[int] = []
    for rule in rules:
        sql, params = compile_rule(rule)
        cur = con.execute(sql, params)
        cols = [c[0] for c in cur.description]
        for values in cur.fetchall():
            row = dict(zip(cols, values))
            det = _detection(rule, row)
            detections.append(det)
            det_ids.extend([det.detection_id] * len(row["lines"]))
            line_nos.extend(row["lines"])
    tbl = pa.table({"detection_id": pa.array(det_ids, pa.string()),
                    "line_no": pa.array(line_nos, pa.int64())})
    con.register("_det_events", tbl)
    con.execute("CREATE OR REPLACE TABLE detection_events AS SELECT * FROM _det_events")
    con.unregister("_det_events")
    detections.sort(key=lambda d: (d.first_seen, d.rule_id))
    return detections
