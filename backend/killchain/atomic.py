"""Atomic file writes: readers never see a half-written file."""
from __future__ import annotations

import json
import os
from pathlib import Path


def write_text_atomic(path: Path, text: str) -> None:
    path = Path(path)
    tmp = path.parent / f".{path.name}.tmp"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def write_json_atomic(path: Path, obj, indent: int = 1) -> None:
    write_text_atomic(path, json.dumps(obj, indent=indent))
