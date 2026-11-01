"""Per-cycle change feed for live mode: diff incidents.json cycles into changes.jsonl."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

CHANGES_FILE = "changes.jsonl"


def diff_cycle(
    prev: dict[int, dict],
    cur: dict[int, dict],
    renumber: dict,
    *,
    cycle: int,
    generation: int,
    pct: float,
) -> dict:
    new = [int(i) for i in renumber.get("new", [])]
    merged = [
        {"from": int(a), "into": int(b)} for a, b in (renumber.get("merged") or {}).items()
    ]
    withdrawn = [int(i) for i in renumber.get("withdrawn", [])]

    grew = []
    for iid, inc in cur.items():
        if iid not in prev:
            continue
        seen = {d["detection_id"] for d in prev[iid].get("detections", [])}
        steps = [
            {
                "technique_id": d["technique"]["id"],
                "technique_name": d["technique"]["name"],
            }
            for d in inc.get("detections", [])
            if d["detection_id"] not in seen
        ]
        if steps:
            grew.append({"id": iid, "steps": steps})

    headlines = [f"#{i} new: {cur[i]['title']}" if i in cur else f"#{i} new" for i in new]
    for g in grew:
        headlines += [
            f"#{g['id']} gained step {s['technique_id']} {s['technique_name']}"
            for s in g["steps"]
        ]
    headlines += [f"#{m['from']} merged into #{m['into']}" for m in merged]
    headlines += [f"#{i} withdrawn" for i in withdrawn]

    return {
        "generation": generation,
        "cycle": cycle,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "pct": pct,
        "new": new,
        "grew": grew,
        "merged": merged,
        "withdrawn": withdrawn,
        "headlines": headlines,
    }


def append_change(run_dir: Path, entry: dict) -> None:
    with (Path(run_dir) / CHANGES_FILE).open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_changes(run_dir: Path, since_generation: int = 0) -> list[dict]:
    path = Path(run_dir) / CHANGES_FILE
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            if e.get("generation", 0) > since_generation:
                out.append(e)
    return out
