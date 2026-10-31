"""MITRE ATT&CK technique catalogue and kill-chain stage labelling (FR-3)."""
from __future__ import annotations

import functools
from pathlib import Path

import yaml
from pydantic import BaseModel


class TechniqueLabel(BaseModel):
    id: str
    name: str
    tactic: str
    stage: str
    stage_index: int


def _default_path() -> Path:
    from config import get_settings

    return Path(get_settings().KILLCHAIN_MITRE_PATH)


@functools.lru_cache(maxsize=4)
def _load(path: str) -> dict[str, TechniqueLabel]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    order = doc["stage_order"]
    out = {}
    for tid, t in doc["techniques"].items():
        if t["stage"] not in order:
            raise ValueError(f"{tid}: unknown kill-chain stage {t['stage']!r}")
        out[tid] = TechniqueLabel(id=tid, name=t["name"], tactic=t["tactic"], stage=t["stage"],
                                  stage_index=order.index(t["stage"]))
    return out


def stage_order(path: Path | None = None) -> list[str]:
    doc = yaml.safe_load(Path(path or _default_path()).read_text(encoding="utf-8"))
    return list(doc["stage_order"])


def load_catalogue(path: Path | None = None) -> dict[str, TechniqueLabel]:
    return _load(str(path or _default_path()))


def label(technique_id: str) -> TechniqueLabel:
    """Label for a technique id; raises KeyError when it is not in the catalogue."""
    return load_catalogue()[technique_id]
