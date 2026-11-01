"""Stable incident numbers across live cycles: a number follows its detections."""
from __future__ import annotations

import json
from pathlib import Path

from killchain.atomic import write_json_atomic
from killchain.models import Incident


def load_registry(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {"next": 1, "numbers": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def save_registry(path: Path, reg: dict) -> None:
    write_json_atomic(Path(path), reg)


def renumber(incidents: list[Incident], reg: dict) -> dict:
    """Assign stable numbers in place; update reg; return this cycle's changes."""
    numbers = reg["numbers"]
    old = {int(n): set(e["detections"]) for n, e in numbers.items() if e["status"] == "active"}
    dets = [{d.detection_id for d in inc.detections} for inc in incidents]
    assigned: dict[int, int] = {}  # incident index -> number

    for n in sorted(old):  # lowest number chooses first, so merges keep the lower number
        takers = [i for i in range(len(incidents))
                  if i not in assigned and dets[i] & old[n]]
        if takers:
            best = max(takers, key=lambda i: (len(dets[i] & old[n]),
                                              -incidents[i].first_seen.timestamp()))
            assigned[best] = n

    new: list[int] = []
    for i in range(len(incidents)):
        if i not in assigned:
            assigned[i] = reg["next"]
            new.append(reg["next"])
            reg["next"] += 1

    taken = set(assigned.values())
    merged: dict[int, int] = {}
    withdrawn: list[int] = []
    for n in sorted(old):
        if n in taken:
            continue
        overlaps = [(len(dets[i] & old[n]), i) for i in range(len(incidents)) if dets[i] & old[n]]
        if overlaps:
            target = assigned[max(overlaps)[1]]
            numbers[str(n)] = {"status": "merged", "detections": sorted(old[n]),
                               "merged_into": target}
            merged[n] = target
        else:
            numbers[str(n)] = {"status": "withdrawn", "detections": sorted(old[n]),
                               "merged_into": None}
            withdrawn.append(n)

    for i, inc in enumerate(incidents):
        inc.incident_id = assigned[i]
        numbers[str(assigned[i])] = {"status": "active", "detections": sorted(dets[i]),
                                     "merged_into": None}
    return {"new": new, "merged": merged, "withdrawn": withdrawn}


def resolve(reg: dict, number: int) -> dict | None:
    """Where a retired number went: merged_into the final active number, or withdrawn."""
    seen: set[int] = set()
    cur = number
    while True:
        e = reg["numbers"].get(str(cur))
        if e is None or cur in seen:
            return None
        seen.add(cur)
        if e["status"] == "active":
            return {"merged_into": cur} if cur != number else None
        if e["status"] == "withdrawn":
            return {"withdrawn": True}
        cur = e["merged_into"]
