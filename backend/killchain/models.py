"""Pydantic models for the kill-chain pipeline."""
from __future__ import annotations

from pydantic import BaseModel


class IngestStats(BaseModel):
    lines_read: int
    lines_parsed: int
    lines_skipped: int
    parts: int
    seconds: float
    peak_rss_mb: float
