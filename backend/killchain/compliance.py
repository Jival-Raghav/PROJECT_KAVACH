"""Security controls scored from incident evidence.

`gap`: an attack step mapped to the control got through. `attempted`: mapped steps were seen, all
blocked. `no_failure_seen`: no mapped step in this log, which does not prove the control works.
"""
from __future__ import annotations

from pathlib import Path

import yaml

NOTICE = ("Audit aid only: mappings are written by the Kavach team and need checking against the "
          "official standards. A log can show a control failing, not prove that it works.")


def load_controls(path: Path) -> list[dict]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))["controls"]


def evaluate_controls(incidents: dict[int, dict], controls: list[dict]) -> dict:
    rows = []
    ranked = sorted(incidents.values(), key=lambda i: -i.get("risk_score", 0))
    for control in controls:
        wanted = set(control["techniques"])
        failed, attempted = [], []
        for inc in ranked:
            hits = [d for d in inc.get("detections", []) if d["technique"]["id"] in wanted]
            if any(d["outcome"] != "blocked" for d in hits):
                failed.append(inc["incident_id"])
            elif hits:
                attempted.append(inc["incident_id"])
        status = "gap" if failed else "attempted" if attempted else "no_failure_seen"
        rows.append({"id": control["id"], "title": control["title"], "refs": control["refs"],
                     "status": status, "failed_in": failed, "attempted_in": attempted})
    counts = {s: sum(r["status"] == s for r in rows)
              for s in ("gap", "attempted", "no_failure_seen")}
    return {"controls": rows, "counts": counts, "notice": NOTICE}


def incident_controls(inc: dict, controls: list[dict]) -> list[dict]:
    """Controls this incident shows failing or tested."""
    result = evaluate_controls({inc["incident_id"]: inc}, controls)["controls"]
    return [r for r in result if r["status"] != "no_failure_seen"]
