"""Red-team the incident review: put each payload in log text and measure what the LLM would see.

Run from the repo root: python scripts/bench_log_injection.py
This needs no LLM and does not test how a model would react. It measures redaction, and checks
that the verdict stays the same, because the verdict never reads the argument text.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

import yaml  # noqa: E402

from killchain.review import build_evidence, build_review  # noqa: E402


def incident(text: str) -> dict:
    step = {"ts": "2026-10-23T10:00:00+05:30", "technique_id": "T1190", "technique_name": "Exploit",
            "description": text, "outcome": "allowed"}
    return {"incident_id": 1, "severity": "critical", "timeline": [step], "actors": [], "anomaly": [],
            "reach": {"summary": "From 1 host, 3 are reachable.", "footholds": ["10.10.20.20"]}}


def run() -> dict:
    payloads = yaml.safe_load((REPO / "tests/redteam/payloads.yaml").read_text(encoding="utf-8"))["payloads"]
    baseline = build_review(incident("Burst of 60 events"))["verdict"]
    rows = []
    for p in payloads:
        evidence = build_evidence(incident(p["payload"]))[0]
        verdict = build_review(incident(p["payload"]))["verdict"]
        rows.append({"id": p["id"], "category": p["category"], "flagged": evidence["flagged"],
                     "verdict_unchanged": verdict == baseline})
    return {"rows": rows, "total": len(rows), "flagged": sum(r["flagged"] for r in rows),
            "verdict_unchanged": sum(r["verdict_unchanged"] for r in rows)}


def main() -> None:
    result = run()
    lines = ["# Prompt injection through firewall log text", "",
             "Each payload is placed in log-derived text, then passed through the evidence builder "
             "used by the incident review. No LLM was called, so this does not measure how a model "
             "would respond to a payload that gets through.", "",
             f"- Payloads flagged and redacted: **{result['flagged']} / {result['total']}**",
             f"- Verdict unchanged: **{result['verdict_unchanged']} / {result['total']}**", "",
             "| Payload | Category | Flagged | Verdict unchanged |", "|---|---|---|---|"]
    for r in result["rows"]:
        lines.append(f"| {r['id']} | {r['category']} | {'yes' if r['flagged'] else 'NO'} | "
                     f"{'yes' if r['verdict_unchanged'] else 'NO'} |")
    out = REPO / "reports" / "log_injection.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{result['flagged']}/{result['total']} flagged, "
          f"{result['verdict_unchanged']}/{result['total']} verdicts unchanged. Report: {out}")


if __name__ == "__main__":
    main()
