"""Command line: `python -m killchain.cli run|bench` (run from the backend/ directory)."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from config import get_settings

REPO = Path(__file__).resolve().parents[2]

# (metric, how to read it, good test, great test, PRD wording of good/great)
_TARGETS = [
    ("Detection", lambda m: m.detection_rate, lambda v: v > 0.70, lambda v: v > 0.90,
     "> 70% / > 90%", lambda v: f"{v:.1%}"),
    ("Correct labels (strict)", lambda m: m.label_accuracy, lambda v: v > 0.60,
     lambda v: v > 0.85, "> 60% / > 85%", lambda v: f"{v:.1%}"),
    ("Attack path", lambda m: m.paths_rebuilt / max(1, m.paths_total),
     lambda v: v >= 0.5, lambda v: v >= 1.0, "half / all", lambda v: f"{v:.0%}"),
    ("False alarms", lambda m: m.false_alarm_rate, lambda v: v < 0.30, lambda v: v < 0.10,
     "< 30% / < 10%", lambda v: f"{v:.1%}"),
    ("Processing time", lambda m: m.processing_seconds, lambda v: v < 3 * 3600,
     lambda v: v < 3600, "< 3 h / < 1 h", lambda v: f"{v / 60:.1f} min"),
    ("Peak memory", lambda m: m.peak_memory_mb, lambda v: v < 16 * 1024, lambda v: v < 8 * 1024,
     "< 16 GB / < 8 GB", lambda v: f"{v / 1024:.2f} GB"),
    ("Investigation speed (p95 open)", lambda m: m.p95_open_ms, lambda v: v < 2000,
     lambda v: v < 500, "< 2 s / < 500 ms", lambda v: f"{v:.2f} ms"),
]


def _run_dir(run_id: str) -> Path:
    return Path(get_settings().KILLCHAIN_DATA_DIR) / "runs" / run_id


def cmd_run(a: argparse.Namespace) -> None:
    from killchain.pipeline import run_killchain

    log = Path(a.log or get_settings().KILLCHAIN_LOG_PATH)
    if not a.skip_ingest and not log.is_file():
        raise SystemExit(f"Log not found: {log}\nPass --log PATH or set KILLCHAIN_LOG_PATH in .env.")
    meta = run_killchain(log, _run_dir(a.run_id),
                         Path(get_settings().KILLCHAIN_RULES_DIR), skip_ingest=a.skip_ingest,
                         progress=lambda s: print(f"[killchain] {s}", flush=True))
    print(json.dumps(meta, indent=1))


def cmd_live(a: argparse.Namespace) -> None:
    from killchain.live import LiveJob, is_zip, owner_alive, read_state
    from killchain.pipeline import load_run

    def show(e: dict) -> None:
        n = len(load_run(run_dir))
        heads = "; ".join(e.get("headlines", [])[:3])
        print(f"[live] gen {e['generation']} · {e['pct']:.0%} · {n} incidents · {heads}",
              flush=True)

    if a.run_id == "firex":
        raise SystemExit("The firex run cannot be used for live mode")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", a.run_id):
        raise SystemExit(f"Invalid run id: {a.run_id}")
    path = Path(a.path).expanduser()
    if not path.is_file():
        raise SystemExit(f"File not found: {a.path}")
    if not os.access(path, os.R_OK):
        raise SystemExit(f"File is not readable: {a.path}")
    if is_zip(path):
        raise SystemExit(f"Zip archives are not supported: {a.path}")
    run_dir = _run_dir(a.run_id)
    state = read_state(run_dir)
    if state is None and (run_dir / "run_meta.json").exists():
        raise SystemExit(f"Run {a.run_id} is a batch run and cannot be used for live mode")
    if state is not None and owner_alive(state):
        raise SystemExit(f"Run {a.run_id} is being processed by another process")
    s = get_settings()
    try:
        job = LiveJob(run_dir, path, Path(s.KILLCHAIN_RULES_DIR),
                      assets_path=Path(s.KILLCHAIN_ASSETS_PATH), batch_size=a.batch_size,
                      on_cycle=show)
    except ValueError as e:
        raise SystemExit(str(e)) from e
    job.start()
    try:
        while job.is_alive():
            job.join(0.2)
    except KeyboardInterrupt:
        job.stop()
        job.join()
        print("[live] stopped; resume with the same --run-id", flush=True)
        raise SystemExit(130) from None
    status = job.state["status"]
    if status == "error":
        raise SystemExit(f"[live] error: {job.state['error']}")
    if status == "complete":
        print(f"[live] complete: {len(load_run(run_dir))} incidents", flush=True)
    else:
        print("[live] stopped; resume with the same --run-id", flush=True)


def render_benchmark(m, meta: dict) -> str:
    ingest = meta.get("ingest") or {}
    parsed = ingest.get("lines_parsed", 0)
    stalled = sum(s["lines"] for s in meta.get("clock_stalls", []))
    lines = ["# Kill Chain & Attack Path — Benchmark", "",
             f"Dataset: `{Path(meta.get('log_path', '')).name}` — {parsed:,} events parsed, "
             f"{parsed - stalled:,} analysed, {stalled:,} left out under a frozen clock, "
             f"{ingest.get('lines_skipped', 0):,} malformed lines skipped. "
             f"Ground truth: `data/ground_truth/firex_planted.yaml` "
             f"({m.paths_total} scenarios, {m.steps_total} steps; recovered by our own hunt — "
             "the dataset shipped without labels).", "",
             "| What we measure | Result | Good / Great | Rating |", "|---|---|---|---|"]
    for name, get, good, great, wording, fmt in _TARGETS:
        v = get(m)
        rating = "🟢 Great" if great(v) else "🟡 Good" if good(v) else "🔴 Below target"
        shown = fmt(v)
        if name == "Peak memory" and v <= 0:
            shown, rating = "not measured", "⚪ Not measured"
        lines.append(f"| {name} | **{shown}** | {wording} | {rating} |")
    s = meta.get("seconds", {})
    lines += ["", f"Attack paths: {m.paths_rebuilt}/{m.paths_total} scenarios rebuilt, of which "
              f"{m.paths_multistep_rebuilt}/{m.paths_multistep_total} are multi-step chains "
              f"where step order is actually tested. A scenario only counts as rebuilt when its "
              f"incident contains no other scenario. Incidents spanning more than one scenario: "
              f"{m.merged_incidents}. Incident purity (share of an incident's events that are "
              f"planted): {m.incident_purity:.1%}."]
    lines += ["", f"Steps found {m.steps_found}/{m.steps_total}; lenient label accuracy "
              f"{m.label_accuracy_lenient:.1%}; {m.incidents} incidents, {m.false_alarms} false "
              f"alarms; {meta.get('raw_alerts_merged', 0):,} raw alerts merged into "
              f"{m.incidents} incidents (B-3). Cold load of all incidents: {m.cold_open_ms} ms.", "",
              "Stage timings (s): " + ", ".join(f"{k} {v}" for k, v in s.items()), "",
              "## Per scenario", "", "| Scenario | Steps | Path rebuilt | Incident |",
              "|---|---|---|---|"]
    for sc in m.per_scenario:
        lines.append(f"| {sc['scenario']} {sc['name']} | {sc['steps']} | "
                     f"{'yes' if sc['rebuilt'] else 'NO'} | {sc['incident_id'] or '-'} |")
    lines += ["", "## Per step", "", "| Step | Found | Expected | Labelled | OK |",
              "|---|---|---|---|---|"]
    for st in m.per_step:
        lines.append(f"| {st['step']} | {'yes' if st['found'] else 'NO'} | "
                     f"{st['expected'][0]} | {', '.join(st['techniques_found']) or '-'} | "
                     f"{'yes' if st['label_ok'] else 'no'} |")
    lines += ["", "## Honest limits", "",
              "- The ground truth was reconstructed by us from the logs (rare events, the "
              "`crscore` field planted lines carry, periodicity and repeated-pair analysis). "
              "Rules are tested to contain none of its IPs, users or domains.",
              "- The ground truth was widened once during tuning: the first rule run produced 4 "
              "detections outside the then-ground-truth (a false-alarm rate of 4/20 at that "
              "point). On inspection they were planted activity without the `crscore` marker "
              "(periodic 300 s beacons; repeated ~20 KB transfers to the same attacker IPs), so "
              "5 steps were added (GT-07 beacon + exfil, GT-16 scan + exfil, GT-20). The 0% "
              "false-alarm figure is measured against that widened ground truth.",
              "- The supplied file ends in about 1.7 GB of random bytes; those lines are skipped "
              "and counted. Lines sharing one frozen timestamp are kept out of detection, "
              "baselines and the reach graph; processing time and memory still include reading "
              "them.",
              "- Timestamps are the firewall's local clock (+05:30)."]
    return "\n".join(lines) + "\n"


def cmd_bench(a: argparse.Namespace) -> None:
    from killchain.evaluate import evaluate
    from killchain.pipeline import load_meta

    run_dir = _run_dir(a.run_id)
    m = evaluate(run_dir, Path(a.gt or get_settings().KILLCHAIN_GT_PATH))
    meta = load_meta(run_dir)
    out = Path(a.out or REPO / "reports")
    out.mkdir(parents=True, exist_ok=True)
    (out / "killchain_benchmark.json").write_text(
        json.dumps({"metrics": m.model_dump(), "run_meta": meta}, indent=1), encoding="utf-8")
    md = render_benchmark(m, meta)
    (out / "killchain_benchmark.md").write_text(md, encoding="utf-8")
    print(md)


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to a non-UTF-8 code page
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="killchain")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="ingest + detect + correlate + enrich")
    r.add_argument("--log")
    r.add_argument("--run-id", default="firex")
    r.add_argument("--skip-ingest", action="store_true")
    r.set_defaults(fn=cmd_run)
    b = sub.add_parser("bench", help="score a run against the ground truth")
    b.add_argument("--run-id", default="firex")
    b.add_argument("--gt")
    b.add_argument("--out")
    b.set_defaults(fn=cmd_bench)
    lv = sub.add_parser("live", help="stream a log and re-analyse as it is read")
    lv.add_argument("--path", required=True)
    lv.add_argument("--run-id", default="live")
    lv.add_argument("--batch-size", type=int, default=200_000)
    lv.set_defaults(fn=cmd_live)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
