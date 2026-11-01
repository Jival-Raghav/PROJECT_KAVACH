"""Pydantic models for the kill-chain pipeline."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from killchain.mitre import TechniqueLabel

Severity = Literal["low", "medium", "high", "critical"]


class IngestStats(BaseModel):
    lines_read: int
    lines_parsed: int
    lines_skipped: int
    lines_stalled: int = 0  # parsed, but under a frozen clock: kept out of detection
    parts: int
    seconds: float
    peak_rss_mb: float  # with workers: main process plus each worker's own peak, an upper bound
    workers: int = 1


class Detection(BaseModel):
    detection_id: str
    rule_id: str
    title: str
    technique: TechniqueLabel
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    event_count: int
    sample_line_nos: list[int] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    outcome: Literal["allowed", "blocked", "mixed"] = "allowed"
    summary: str = ""


class Incident(BaseModel):
    incident_id: int
    title: str
    detections: list[Detection]
    first_seen: datetime
    last_seen: datetime
    entities: dict[str, list[str]] = Field(default_factory=dict)
    tactics: list[str] = Field(default_factory=list)
    stages: list[str] = Field(default_factory=list)
    raw_alert_count: int = 0
    risk_score: float = 0.0
    severity: str = "low"
