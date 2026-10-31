"""backend/llm/jsonutil.py
Tolerant JSON extraction shared by the prosecutor, devil's advocate and adjudicator.

Models wrap JSON in markdown fences, prepend reasoning prose, or append commentary.
`parse_llm_json` returns the first decodable JSON object in the text, or None.
"""
from __future__ import annotations

import json
import re
from typing import Any

_FENCE = re.compile(r"```(?:json)?", re.IGNORECASE)


def parse_llm_json(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    text = _FENCE.sub("", raw).strip()
    decoder = json.JSONDecoder()
    idx = text.find("{")
    while idx != -1:
        try:
            obj, _ = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            idx = text.find("{", idx + 1)
            continue
        if isinstance(obj, dict):
            return obj
        idx = text.find("{", idx + 1)
    return None
