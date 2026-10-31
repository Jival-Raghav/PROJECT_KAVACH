"""PRD metrics against the ground truth (detection, labels, paths, false alarms, time, memory)."""
from __future__ import annotations

import random
import time
from pathlib import Path

from pydantic import BaseModel

from killchain.groundtruth import load_ground_truth, resolve_steps
from killchain.pipeline import clear_cache, load_meta, load_run
from killchain.store import open_events


class Metrics(BaseModel):
    detection_rate: float
    label_accuracy: float
    label_accuracy_lenient: float
    paths_rebuilt: int
    paths_total: int
    false_alarm_rate: float
    incidents: int
    false_alarms: int
    steps_total: int
    steps_found: int
    processing_seconds: float
    peak_memory_mb: float
    cold_open_ms: float
    p95_open_ms: float
    per_step: list[dict]
    per_scenario: list[dict]


def _det_lines(run_dir: Path) -> dict[str, set[int]]:
    con = open_events(run_dir)
    rows = con.execute(
        f"SELECT detection_id, line_no FROM read_parquet('{run_dir / 'detection_events.parquet'}')"
    ).fetchall()
    out: dict[str, set[int]] = {}
    for det_id, ln in rows:
        out.setdefault(det_id, set()).add(ln)
    return out


def _open_latency(run_dir: Path) -> tuple[float, float]:
    clear_cache()
    t = time.perf_counter()
    ids = list(load_run(run_dir))
    if ids:
        _ = load_run(run_dir)[ids[0]]["path"]
    cold = (time.perf_counter() - t) * 1000
    rnd = random.Random(0)
    samples = []
    for _ in range(100):
        t = time.perf_counter()
        inc = load_run(run_dir).get(rnd.choice(ids)) if ids else None
        _ = (inc or {}).get("path"), (inc or {}).get("timeline")
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    return round(cold, 2), round(samples[int(len(samples) * 0.95) - 1], 3)


def evaluate(run_dir: Path, gt_path: Path) -> Metrics:
    run_dir = Path(run_dir)
    scenarios = load_ground_truth(gt_path)
    steps = resolve_steps(open_events(run_dir), scenarios)
    det_lines = _det_lines(run_dir)
    incidents = load_run(run_dir)
    det_info = {d["detection_id"]: (inc_id, d["technique"]["id"], d["first_seen"])
                for inc_id, inc in incidents.items() for d in inc["detections"]}
    gt_lines = set().union(*steps.values()) if steps else set()

    per_step, found, strict, lenient = [], 0, 0, 0
    covering: dict[str, list[str]] = {}
    for sc in scenarios:
        for st in sc.steps:
            dets = sorted(d for d, ls in det_lines.items() if ls & steps[st.id])
            covering[st.id] = dets
            techs = sorted({det_info[d][1] for d in dets if d in det_info})
            ok_strict = st.techniques[0] in techs
            ok_len = bool(set(techs) & set(st.techniques))
            found += bool(dets)
            strict += bool(dets) and ok_strict
            lenient += bool(dets) and ok_len
            per_step.append({"step": st.id, "scenario": sc.id, "found": bool(dets),
                             "techniques_found": techs, "expected": st.techniques,
                             "label_ok": ok_strict, "events": len(steps[st.id])})

    per_scenario, rebuilt = [], 0
    for sc in scenarios:
        ok_inc = None
        for inc_id in incidents:
            times = []
            for st in sc.steps:
                ts = [det_info[d][2] for d in covering[st.id]
                      if d in det_info and det_info[d][0] == inc_id]
                if not ts:
                    break
                times.append(min(ts))
            else:
                if times == sorted(times):
                    ok_inc = inc_id
                    break
        rebuilt += ok_inc is not None
        per_scenario.append({"scenario": sc.id, "name": sc.name, "steps": len(sc.steps),
                             "rebuilt": ok_inc is not None, "incident_id": ok_inc})

    false_alarms = 0
    for inc in incidents.values():
        lines = set().union(*(det_lines.get(d["detection_id"], set()) for d in inc["detections"]))
        false_alarms += not (lines & gt_lines)

    total_steps = len(per_step)
    meta = load_meta(run_dir)
    cold, p95 = _open_latency(run_dir)
    return Metrics(
        detection_rate=round(found / total_steps, 4) if total_steps else 0.0,
        label_accuracy=round(strict / found, 4) if found else 0.0,
        label_accuracy_lenient=round(lenient / found, 4) if found else 0.0,
        paths_rebuilt=rebuilt, paths_total=len(scenarios),
        false_alarm_rate=round(false_alarms / len(incidents), 4) if incidents else 0.0,
        incidents=len(incidents), false_alarms=false_alarms, steps_total=total_steps,
        steps_found=found, processing_seconds=float(meta.get("total_seconds", 0.0)),
        peak_memory_mb=float(meta.get("peak_rss_mb", 0.0)), cold_open_ms=cold, p95_open_ms=p95,
        per_step=per_step, per_scenario=per_scenario,
    )
