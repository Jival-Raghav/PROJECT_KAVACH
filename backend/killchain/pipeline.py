"""End-to-end kill-chain run: ingest → detect → correlate → score → path/reach/report → persist."""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from killchain.accounts import audit_accounts
from killchain.actors import build_actors, link_incidents
from killchain.anomaly import incident_entities, score_entities, split_scores
from config import get_settings
from killchain.compliance import incident_controls, load_controls
from killchain.correlate import correlate
from killchain.response import build_actions
from killchain.ingest import ingest_log, peak_rss_mb
from killchain.models import Incident
from killchain.pathgraph import build_path, build_timeline, format_ts
from killchain.reach import build_network_graph, load_assets, next_reach
from killchain.report import render_report
from killchain.review import build_review
from killchain.rules import load_rules, run_rules
from killchain.scoring import rank
from killchain.store import load_clock_stalls, open_events, sql_str

_CACHE: dict[str, tuple[float, dict[int, dict]]] = {}


def _incident_json(inc: Incident, con_graph, assets) -> dict:
    timeline = build_timeline(inc)
    reach = next_reach(inc, con_graph, assets)
    data = inc.model_dump(mode="json")
    data["first_seen"], data["last_seen"] = format_ts(inc.first_seen), format_ts(inc.last_seen)
    for d_json, d in zip(data["detections"], inc.detections):
        d_json["first_seen"], d_json["last_seen"] = format_ts(d.first_seen), format_ts(d.last_seen)
    data["detection_count"] = len(inc.detections)
    data["timeline"] = [s.model_dump() for s in timeline]
    data["path"] = build_path(inc, firewall_ip=assets.get("firewall_mgmt_ip", ""),
                              assets=assets).model_dump()
    data["reach"] = reach.model_dump()
    data["report"] = render_report(inc, timeline, reach, use_llm=False)
    return data


def run_killchain(log_path: Path, run_dir: Path, rules_dir: Path, skip_ingest: bool = False,
                  assets_path: Path | None = None,
                  progress: Callable[[str], None] | None = None,
                  schema_path: Path | None = None) -> dict:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda _s: None)
    meta_path = run_dir / "run_meta.json"
    old = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    seconds: dict[str, float] = {}

    t = time.perf_counter()
    if skip_ingest and any((run_dir / "events").glob("*.parquet")):
        ingest = old.get("ingest")
        seconds["ingest"] = float(old.get("seconds", {}).get("ingest", 0.0))
    else:
        if schema_path is None:
            from killchain.onboard import choose_parser

            schema_path = choose_parser(Path(log_path), progress=say)
        say("ingest")
        ingest = ingest_log(Path(log_path), run_dir,
                            workers=get_settings().KILLCHAIN_INGEST_WORKERS,
                            schema_path=schema_path).model_dump()
        seconds["ingest"] = round(time.perf_counter() - t, 2)

    say("detect")
    t = time.perf_counter()
    con = open_events(run_dir)
    rules = load_rules(Path(rules_dir))
    detections = run_rules(con, rules)
    out_path = sql_str(str(run_dir / "detection_events.parquet"))
    con.execute(f"COPY detection_events TO {out_path} (FORMAT parquet)")
    seconds["detect"] = round(time.perf_counter() - t, 2)

    say("correlate")
    t = time.perf_counter()
    incidents = rank(correlate(detections))
    seconds["correlate"] = round(time.perf_counter() - t, 2)

    say("enrich")
    t = time.perf_counter()
    assets = load_assets(assets_path)
    graph = build_network_graph(con, assets)
    out = [_incident_json(inc, graph, assets) for inc in incidents]
    seconds["enrich"] = round(time.perf_counter() - t, 2)

    say("anomaly")
    t = time.perf_counter()
    named = set().union(*(incident_entities(inc) for inc in incidents)) if incidents else set()
    leads, context = split_scores(score_entities(con, named), incidents)
    seconds["anomaly"] = round(time.perf_counter() - t, 2)

    say("actors")
    t = time.perf_counter()
    actors = build_actors(con)
    actor_links = link_incidents(actors, incidents)
    seconds["actors"] = round(time.perf_counter() - t, 2)

    controls = load_controls(Path(get_settings().KILLCHAIN_CONTROLS_PATH))
    for data in out:  # context only: risk scores and the incident list are already final
        data["anomaly"] = context.get(data["incident_id"], [])
        data["actors"] = actor_links.get(data["incident_id"], [])
        data["review"] = build_review(data)
        data["response"] = build_actions(data)
        data["compliance"] = incident_controls(data, controls)
    (run_dir / "anomalies.json").write_text(json.dumps(leads, indent=1), encoding="utf-8")
    (run_dir / "actors.json").write_text(json.dumps(actors, indent=1), encoding="utf-8")
    (run_dir / "accounts.json").write_text(
        json.dumps(audit_accounts(con, actors), indent=1), encoding="utf-8")
    (run_dir / "incidents.json").write_text(json.dumps(out, indent=1), encoding="utf-8")

    meta = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "log_path": str(log_path) if not skip_ingest else old.get("log_path", str(log_path)),
        "ingest": ingest,
        "clock_stalls": load_clock_stalls(run_dir),
        "seconds": seconds,
        "total_seconds": round(sum(seconds.values()), 2),
        "peak_rss_mb": round(max(peak_rss_mb(), float((ingest or {}).get("peak_rss_mb", 0))), 1),
        "rule_count": len(rules),
        "detection_count": len(detections),
        "incident_count": len(incidents),
        "anomaly_lead_count": len(leads),
        "raw_alerts_merged": sum(i.raw_alert_count for i in incidents),
    }
    source_schema = str(schema_path) if schema_path else old.get("source_schema")
    if source_schema:  # only logs read through a learned schema report what they can support
        from killchain.onboard import load_schema, rule_coverage

        meta["source_schema"] = source_schema
        meta["schema_reviewed"] = load_schema(Path(source_schema))["approved"] is True
        con = open_events(run_dir)
        meta["rule_coverage"] = rule_coverage(con, rules)
        con.close()
    meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    _CACHE.pop(str(run_dir), None)
    say("done")
    return meta


def load_run(run_dir: Path) -> dict[int, dict]:
    """Incident id → incident JSON, cached in-process until incidents.json changes."""
    path = Path(run_dir) / "incidents.json"
    if not path.exists():
        return {}
    mtime = path.stat().st_mtime
    hit = _CACHE.get(str(run_dir))
    if hit and hit[0] == mtime:
        return hit[1]
    data = {inc["incident_id"]: inc for inc in json.loads(path.read_text(encoding="utf-8"))}
    _CACHE[str(run_dir)] = (mtime, data)
    return data


def load_anomalies(run_dir: Path) -> list[dict]:
    path = Path(run_dir) / "anomalies.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def load_accounts(run_dir: Path) -> list[dict]:
    path = Path(run_dir) / "accounts.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def load_actors(run_dir: Path) -> list[dict]:
    path = Path(run_dir) / "actors.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def load_meta(run_dir: Path) -> dict:
    path = Path(run_dir) / "run_meta.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def clear_cache() -> None:
    _CACHE.clear()
