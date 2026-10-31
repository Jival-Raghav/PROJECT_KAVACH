"""
config.py — single source of truth for all settings.
Reads from .env at startup. Import get_settings() wherever you need config.
"""
from __future__ import annotations

import functools
import os
from enum import Enum
from typing import Optional

from dotenv import load_dotenv

load_dotenv(override=True)


class LLMProvider(str, Enum):
    LMSTUDIO = "lmstudio"
    OLLAMA = "ollama"
    GROQ = "groq"
    HUGGINGFACE = "huggingface"
    NONE = "none"


class Settings:
    # ── Dual-pass LLM providers ─────────────────────────────────────────────
    # Pass 1 (Prosecutor):  which provider builds the accusation
    PROSECUTOR_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("PROSECUTOR_PROVIDER", "lmstudio").lower()
    )
    # Pass 2 (Devil's Advocate): which provider challenges the accusation
    DA_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("DA_PROVIDER", "ollama").lower()
    )

    # Legacy single-provider key (used when PROSECUTOR_PROVIDER is not set explicitly)
    LLM_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("LLM_PROVIDER", "lmstudio").lower()
    )

    # ── LM Studio (local OpenAI-compatible server) ───────────────────────────
    LMSTUDIO_BASE_URL: str = os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
    LMSTUDIO_MODEL: str = os.getenv("LMSTUDIO_MODEL", "")  # empty = auto-detect

    # ── Ollama (local, OpenAI-compatible at /v1) ──────────────────────────────
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "")  # empty = auto-detect first loaded

    # ── Groq ─────────────────────────────────────────────────────────────────
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # ── HuggingFace ───────────────────────────────────────────────────────────
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")
    HF_MODEL_ID: str = os.getenv(
        "HF_MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.2"
    )

    # ── ML / Pipeline ─────────────────────────────────────────────────────────
    ISOLATION_FOREST_CONTAMINATION: float = float(
        os.getenv("IF_CONTAMINATION", "0.15")
    )
    KMEANS_K: int = int(os.getenv("KMEANS_K", "5"))
    STALE_DAYS_THRESHOLD: int = int(os.getenv("STALE_DAYS_THRESHOLD", "30"))
    VERY_STALE_DAYS_THRESHOLD: int = int(os.getenv("VERY_STALE_DAYS_THRESHOLD", "90"))

    # ── Data paths ────────────────────────────────────────────────────────────
    DATA_DIR: str = os.path.join(os.path.dirname(__file__), "data")


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
