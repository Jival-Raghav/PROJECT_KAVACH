"""End-to-end kill-chain run: ingest → detect → correlate → score → path/reach/report → persist."""
from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from killchain.accounts import audit_accounts
from killchain.actors import build_actors, link_incidents
from killchain.atomic import write_json_atomic
from killchain.anomaly import incident_entities, score_entities, split_scores
from config import get_settings
from killchain.compliance import incident_controls, load_controls
from killchain.correlate import correlate
from killchain.response import build_actions
from killchain.ingest import ingest_log, peak_rss_mb
from killchain.models import Incident
from killchain.pathgraph import build_path, build_timeline, format_ts
from killchain.reach import build_network_graph, load_assets, next_reach
from killchain.registry import load_registry, renumber, save_registry
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
                  progress: Callable[[str], None] | None = None) -> dict:
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
        say("ingest")
        ingest = ingest_log(Path(log_path), run_dir).model_dump()
        seconds["ingest"] = round(time.perf_counter() - t, 2)

    log = str(log_path) if not skip_ingest else old.get("log_path", str(log_path))
    return analyse_run(run_dir, rules_dir, assets_path=assets_path, progress=progress,
                       seconds=seconds, meta_extra={"log_path": log, "ingest": ingest})


def analyse_run(run_dir: Path, rules_dir: Path, *, assets_path: Path | None = None,
                progress: Callable[[str], None] | None = None,
                parts: list[Path] | None = None, seconds: dict[str, float] | None = None,
                meta_extra: dict | None = None,
                registry_path: Path | None = None) -> dict:
    """Everything after ingest: detect → correlate → enrich → anomaly → actors → persist."""
    run_dir = Path(run_dir)
    say = progress or (lambda _s: None)
    seconds = dict(seconds or {})
    meta_extra = meta_extra or {}
    ingest = meta_extra.get("ingest")

    say("detect")
    t = time.perf_counter()
    con = open_events(run_dir, parts=parts)
    rules = load_rules(Path(rules_dir))
    detections = run_rules(con, rules)
    out_path = run_dir / "detection_events.parquet"
    tmp_path = run_dir / ".detection_events.parquet.tmp"
    con.execute(f"COPY detection_events TO {sql_str(str(tmp_path))} (FORMAT parquet)")
    os.replace(tmp_path, out_path)
    seconds["detect"] = round(time.perf_counter() - t, 2)

    say("correlate")
    t = time.perf_counter()
    incidents = rank(correlate(detections))
    renumbered = None
    if registry_path is not None:
        reg = load_registry(registry_path)
        renumbered = renumber(incidents, reg)
        save_registry(registry_path, reg)
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
    write_json_atomic(run_dir / "anomalies.json", leads)
    write_json_atomic(run_dir / "actors.json", actors)
    write_json_atomic(run_dir / "accounts.json", audit_accounts(con, actors))
    write_json_atomic(run_dir / "incidents.json", out)

    meta = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "log_path": meta_extra.get("log_path", ""),
        "ingest": ingest,
        "clock_stalls": load_clock_stalls(run_dir, parts),
        "seconds": seconds,
        "total_seconds": round(sum(seconds.values()), 2),
        "peak_rss_mb": round(max(peak_rss_mb(), float((ingest or {}).get("peak_rss_mb", 0))), 1),
        "rule_count": len(rules),
        "detection_count": len(detections),
        "incident_count": len(incidents),
        "anomaly_lead_count": len(leads),
        "raw_alerts_merged": sum(i.raw_alert_count for i in incidents),
    }
    if renumbered is not None:
        meta["renumber"] = renumbered
    write_json_atomic(run_dir / "run_meta.json", meta)
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
