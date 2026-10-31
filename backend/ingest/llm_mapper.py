"""backend/ingest/llm_mapper.py
LLM-assisted schema mapping proposal with strict JSON validation,
fallback to heuristic candidates, and few-shot feedback injection.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from ingest.heuristic_mapper import (
    CANONICAL_FIELDS,
    compute_source_fingerprint,
    get_past_feedback,
    map_columns_heuristic,
)
from ingest.profiler import TableProfile

logger = logging.getLogger(__name__)


class LLMMappingItem(BaseModel):
    canonical_field: str
    source_column: str
    transform: dict[str, Any] = Field(default_factory=lambda: {"op": "identity", "args": {}})
    confidence: float = 0.8
    rationale: str = ""


class LLMMapperResponse(BaseModel):
    table_role: str
    mappings: list[LLMMappingItem] = Field(default_factory=list)
    unmapped_source_columns: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _clean_json_response(raw_text: str) -> str:
    """Strip markdown code blocks, backticks, and whitespace."""
    s = raw_text.strip()
    if s.startswith("```"):
        lines = s.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    return s


def propose_mapping(
    table_profile: TableProfile,
    target_role: str | None = None,
    use_llm: bool = True,
) -> LLMMapperResponse:
    """Propose mappings using Heuristic + LLM (if available), fused with confidence scoring."""
    role = target_role or table_profile.suggested_role
    if role not in CANONICAL_FIELDS:
        role = "events"

    # Step 1: Compute heuristic candidate mappings
    heuristic_candidates = map_columns_heuristic(table_profile, target_role=role)
    heuristic_map = {m.canonical_field: m for m in heuristic_candidates}

    col_names = [c.name for c in table_profile.columns]
    fingerprint = compute_source_fingerprint(col_names)
    past_feedback = get_past_feedback(fingerprint)

    llm_succeeded = False
    llm_resp: LLMMapperResponse | None = None

    if use_llm:
        # Only call LLM if configured and not replay-only without cache
        try:
            from llm.client import get_llm_client
            client = get_llm_client()

            # Build prompt
            col_summaries = []
            for col in table_profile.columns:
                samples_str = ", ".join(f"'{v}'" for v in col.top_values[:3] if v is not None)
                col_summaries.append(
                    f"- '{col.name}' (type: {col.dtype}, semantic: {col.semantic_type}, sample: [{samples_str}])"
                )
            columns_block = "\n".join(col_summaries)

            canonical_block = ", ".join(CANONICAL_FIELDS.get(role, []))

            feedback_block = ""
            if past_feedback:
                items = [f"Column '{k}' was previously mapped by human to '{v[0]}'" for k, v in past_feedback.items()]
                feedback_block = "\nPast verified human corrections for this source format:\n" + "\n".join(items)

            system_prompt = (
                "You are an expert data engineer mapping source columns to a canonical security schema.\n"
                "Return ONLY valid JSON matching this schema:\n"
                "{\n"
                '  "table_role": "' + role + '",\n'
                '  "mappings": [\n'
                '    {"canonical_field": "...", "source_column": "...", "transform": {"op": "...", "args": {}}, "confidence": 0.95, "rationale": "..."}\n'
                "  ],\n"
                '  "unmapped_source_columns": ["..."],\n'
                '  "warnings": ["..."]\n'
                "}\n"
                "Available transforms: identity, lower, upper, strip, parse_datetime, epoch_s, epoch_ms, bool_map, arn_user, domain_strip."
            )

            user_prompt = (
                f"Target canonical schema fields for role '{role}': {canonical_block}\n\n"
                f"Source table columns:\n{columns_block}\n"
                f"{feedback_block}\n\n"
                "Produce the mapping JSON."
            )

            raw_out = client.chat([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ], temperature=0.1)

            cleaned = _clean_json_response(raw_out)
            data = json.loads(cleaned)
            llm_resp = LLMMapperResponse.model_validate(data)
            llm_succeeded = True
        except Exception as e:
            logger.debug("LLM mapper unavailable or returned invalid JSON (%s); using heuristic.", e)

    # Step 2: Fuse Heuristic and LLM mappings
    final_mappings: list[LLMMappingItem] = []
    mapped_sources: set[str] = set()

    if llm_succeeded and llm_resp:
        for lm in llm_resp.mappings:
            c_fld = lm.canonical_field
            if c_fld in CANONICAL_FIELDS.get(role, []):
                h_cand = heuristic_map.get(c_fld)
                # Compute fused confidence: 0.5 * heuristic + 0.5 * llm
                h_conf = h_cand.confidence if (h_cand and h_cand.source_column == lm.source_column) else 0.5
                fused_conf = round(0.5 * h_conf + 0.5 * lm.confidence, 2)

                final_mappings.append(LLMMappingItem(
                    canonical_field=c_fld,
                    source_column=lm.source_column,
                    transform=lm.transform or {"op": "identity", "args": {}},
                    confidence=fused_conf,
                    rationale=lm.rationale or "Fused LLM and heuristic match",
                ))
                mapped_sources.add(lm.source_column)

    # Add any remaining heuristic mappings not covered by LLM
    already_mapped_canonical = {m.canonical_field for m in final_mappings}
    for h in heuristic_candidates:
        if h.canonical_field not in already_mapped_canonical and h.source_column not in mapped_sources:
            final_mappings.append(LLMMappingItem(
                canonical_field=h.canonical_field,
                source_column=h.source_column,
                transform=h.transform,
                confidence=h.confidence,
                rationale=h.rationale,
            ))
            mapped_sources.add(h.source_column)

    unmapped = [c for c in col_names if c not in mapped_sources]
    warnings = []
    if "resource_sensitivity" not in {m.canonical_field for m in final_mappings} and role == "events":
        warnings.append("No sensitivity classification column found; falling back to default sensitivity.")

    return LLMMapperResponse(
        table_role=role,
        mappings=final_mappings,
        unmapped_source_columns=unmapped,
        warnings=warnings,
    )
