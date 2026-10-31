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

    # ── Guardrails ────────────────────────────────────────────────────────────
    LLM_REPLAY_ONLY: bool = os.getenv("LLM_REPLAY_ONLY", "0").lower() in ("1", "true", "yes")

    # ── Kill chain & attack path (hackathon PRD) ──────────────────────────────
    KILLCHAIN_LOG_PATH: str = os.getenv(
        "KILLCHAIN_LOG_PATH", str(root_dir / "REAL_10G_DATA" / "firex-10G.log")
    )
    KILLCHAIN_DATA_DIR: str = os.getenv("KILLCHAIN_DATA_DIR", str(base_dir / "data" / "killchain"))
    KILLCHAIN_RUN_ID: str = os.getenv("KILLCHAIN_RUN_ID", "firex")
    KILLCHAIN_DUCKDB_MEMORY: str = os.getenv("KILLCHAIN_DUCKDB_MEMORY", "7GB")
    KILLCHAIN_INGEST_WORKERS: int = int(os.getenv("KILLCHAIN_INGEST_WORKERS", "6"))
    KILLCHAIN_RULES_DIR: str = os.getenv(
        "KILLCHAIN_RULES_DIR", str(root_dir / "config" / "detection_rules")
    )
    KILLCHAIN_MITRE_PATH: str = os.getenv(
        "KILLCHAIN_MITRE_PATH", str(root_dir / "config" / "mitre_techniques.yaml")
    )
    KILLCHAIN_ASSETS_PATH: str = os.getenv(
        "KILLCHAIN_ASSETS_PATH", str(root_dir / "config" / "assets.yaml")
    )
    KILLCHAIN_CONTROLS_PATH: str = os.getenv(
        "KILLCHAIN_CONTROLS_PATH", str(root_dir / "config" / "firewall_controls.yaml")
    )
    KILLCHAIN_GT_PATH: str = os.getenv(
        "KILLCHAIN_GT_PATH", str(root_dir / "data" / "ground_truth" / "firex_planted.yaml")
    )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
