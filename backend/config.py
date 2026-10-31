"""
config.py — single source of truth for all settings.
Reads from .env at startup. Import get_settings() wherever you need config.
"""
from __future__ import annotations

import functools
import os
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv

# Search for .env in current file dir and root dir
base_dir = Path(__file__).resolve().parent
root_dir = base_dir.parent
for env_path in (root_dir / ".env", base_dir / ".env"):
    if env_path.exists():
        load_dotenv(env_path, override=True)


class LLMProvider(str, Enum):
    LMSTUDIO = "lmstudio"
    OLLAMA = "ollama"
    GROQ = "groq"
    HUGGINGFACE = "huggingface"
    NONE = "none"


class Settings:
    # ── Providers per role ──────────────────────────────────────────────────
    PROSECUTOR_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("PROSECUTOR_PROVIDER", "groq").lower()
    )
    DA_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("DA_PROVIDER", "groq").lower()
    )
    ADJUDICATOR_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("ADJUDICATOR_PROVIDER", "groq").lower()
    )
    MAPPER_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("MAPPER_PROVIDER", "groq").lower()
    )
    GUARD_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("GUARD_PROVIDER", "groq").lower()
    )

    # Legacy single-provider key
    LLM_PROVIDER: LLMProvider = LLMProvider(
        os.getenv("LLM_PROVIDER", "groq").lower()
    )

    # ── LM Studio (local OpenAI-compatible server) ───────────────────────────
    LMSTUDIO_BASE_URL: str = os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
    LMSTUDIO_MODEL: str = os.getenv("LMSTUDIO_MODEL", "")

    # ── Ollama (local, OpenAI-compatible at /v1) ──────────────────────────────
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "")

    # ── Groq ─────────────────────────────────────────────────────────────────
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # ── HuggingFace ───────────────────────────────────────────────────────────
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")
    HF_MODEL_ID: str = os.getenv("HF_MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.2")

    # ── Guardrails & Concurrency ──────────────────────────────────────────────
    LLM_TOP_K: int = int(os.getenv("LLM_TOP_K", "25"))
    LLM_REPLAY_ONLY: bool = os.getenv("LLM_REPLAY_ONLY", "0").lower() in ("1", "true", "yes")
    RANDOM_SEED: int = int(os.getenv("RANDOM_SEED", "42"))

    # ── ML / Pipeline ─────────────────────────────────────────────────────────
    ISOLATION_FOREST_CONTAMINATION: float = float(
        os.getenv("IF_CONTAMINATION", "0.35")
    )
    IF_SELF_CALIBRATE: bool = os.getenv("IF_SELF_CALIBRATE", "1").lower() in ("1", "true", "yes")
    KMEANS_K: int = int(os.getenv("KMEANS_K", "5"))
    STALE_DAYS_THRESHOLD: int = int(os.getenv("STALE_DAYS_THRESHOLD", "30"))
    VERY_STALE_DAYS_THRESHOLD: int = int(os.getenv("VERY_STALE_DAYS_THRESHOLD", "90"))
    DORMANT_DAYS: int = int(os.getenv("DORMANT_DAYS", "90"))
    UNUSED_ENTITLEMENT_DAYS: int = int(os.getenv("UNUSED_ENTITLEMENT_DAYS", "90"))
    WHATIF_REPLAY_DAYS: int = int(os.getenv("WHATIF_REPLAY_DAYS", "60"))
    WEIGHT_ML: float = float(os.getenv("WEIGHT_ML", "0.60"))
    WEIGHT_HEURISTICS: float = float(os.getenv("WEIGHT_HEURISTICS", "0.40"))
    PEER_ZSCORE_THRESHOLD: float = float(os.getenv("PEER_ZSCORE_THRESHOLD", "2.0"))
    SOD_CONFIG_PATH: str = os.getenv(
        "SOD_CONFIG_PATH", str(root_dir / "config" / "sod.yaml")
    )


    # ── Paths ─────────────────────────────────────────────────────────────────
    DATA_DIR: str = os.path.join(os.path.dirname(__file__), "data")
    DB_PATH: str = os.getenv(
        "DB_PATH", os.path.join(os.path.dirname(__file__), "data", "ispad.db")
    )
    CACHE_DIR: str = os.path.join(os.path.dirname(__file__), "data", "cache")


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
