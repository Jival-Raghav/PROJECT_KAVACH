"""Ground-truth scenarios (planted attacks) and their resolution to log lines."""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml
from pydantic import BaseModel


class GTStep(BaseModel):
    id: str
    techniques: list[str]
    where: str
    expected_count: int


class GTScenario(BaseModel):
    id: str
    name: str
    steps: list[GTStep]


def load_ground_truth(path: Path) -> list[GTScenario]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [GTScenario(**s) for s in doc["scenarios"]]


def resolve_steps(con, scenarios: list[GTScenario]) -> dict[str, set[int]]:
    """Step id -> set of matching `line_no` values."""
    out: dict[str, set[int]] = {}
    for sc in scenarios:
        for st in sc.steps:
            rows = con.execute(f"SELECT line_no FROM events WHERE {st.where}").fetchall()
            out[st.id] = {r[0] for r in rows}
    return out


def _check(gt_path: Path, run_dir: Path) -> int:
    from killchain.store import open_events

    scenarios = load_ground_truth(gt_path)
    steps = resolve_steps(open_events(run_dir), scenarios)
    bad = 0
    for sc in scenarios:
        for st in sc.steps:
            n = len(steps[st.id])
            ok = n == st.expected_count
            bad += not ok
            print(f"{st.id:10} {n:6} {st.expected_count:6} {'OK' if ok else 'MISMATCH'}")
    return bad


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--check", required=True, type=Path, help="ground-truth yaml")
    p.add_argument("run_dir", type=Path)
    a = p.parse_args()
    raise SystemExit(1 if _check(a.check, a.run_dir) else 0)
