"""
llm/client.py
Provider-agnostic LLM client.

Priority: use whichever provider is set in LLM_PROVIDER env var.
If that provider fails, raise a clear ProviderError — no silent fallback.

Supports:
  - lmstudio   → OpenAI-compatible local server (http://localhost:1234/v1)
  - groq       → Groq cloud API
  - huggingface → HuggingFace Inference API
  - none       → Always returns the deterministic stub
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Iterator

from config import LLMProvider, get_settings

logger = logging.getLogger(__name__)


# ─── Exceptions ──────────────────────────────────────────────────────────────

class ProviderError(RuntimeError):
    """Raised when the configured LLM provider is unavailable or misconfigured."""
    pass


class ProviderNotConfiguredError(ProviderError):
    """Raised when the provider is selected but required credentials/URL are missing."""
    pass


# ─── Abstract Base ────────────────────────────────────────────────────────────

class LLMClient(ABC):
    """Common interface all provider clients must implement."""

    @abstractmethod
    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 1024,
    ) -> str:
        """Blocking call. Returns the full assistant response string."""

    @abstractmethod
    def stream(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 1024,
    ) -> Iterator[str]:
        """Streaming call. Yields text chunks as they arrive."""

    def name(self) -> str:
        return self.__class__.__name__


# ─── LM Studio (OpenAI-compatible) ───────────────────────────────────────────

class LMStudioClient(LLMClient):
    def __init__(self) -> None:
        cfg = get_settings()
        if not cfg.LMSTUDIO_BASE_URL:
            raise ProviderNotConfiguredError(
                "LM Studio is selected (LLM_PROVIDER=lmstudio) but "
                "LMSTUDIO_BASE_URL is not set in .env. "
                "Set it to http://localhost:1234/v1 (default LM Studio port)."
            )
        try:
            from openai import OpenAI
        except ImportError:
            raise ProviderError(
                "openai package is not installed. Run: pip install openai"
            )

        self._model = cfg.LMSTUDIO_MODEL or self._detect_model(cfg.LMSTUDIO_BASE_URL)
        self._client = OpenAI(base_url=cfg.LMSTUDIO_BASE_URL, api_key="lm-studio")
        logger.info("LMStudioClient ready — model: %s", self._model)

    def _detect_model(self, base_url: str) -> str:
        """Auto-detect the first loaded model via GET /v1/models."""
        try:
            from openai import OpenAI
            probe = OpenAI(base_url=base_url, api_key="lm-studio")
            models = probe.models.list()
            if models.data:
                detected = models.data[0].id
                logger.info("LM Studio auto-detected model: %s", detected)
                return detected
        except Exception as exc:
            raise ProviderError(
                f"LM Studio is selected but could not connect to {base_url}. "
                f"Make sure LM Studio is running with a model loaded. "
                f"Error: {exc}"
            ) from exc
        raise ProviderError(
            f"LM Studio is running at {base_url} but no models are loaded. "
            "Please load a model in LM Studio first."
        )

    def chat(self, messages, temperature=0.3, max_tokens=1024) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise ProviderError(
                f"LM Studio request failed. Is LM Studio still running? Error: {exc}"
            ) from exc

    def stream(self, messages, temperature=0.3, max_tokens=1024) -> Iterator[str]:
        try:
            stream = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            raise ProviderError(
                f"LM Studio streaming failed. Error: {exc}"
            ) from exc


# ─── Groq ────────────────────────────────────────────────────────────────────

class GroqClient(LLMClient):
    def __init__(self) -> None:
        cfg = get_settings()
        if not cfg.GROQ_API_KEY:
            raise ProviderNotConfiguredError(
                "Groq is selected (LLM_PROVIDER=groq) but GROQ_API_KEY is not set in .env. "
                "Get a free key at https://console.groq.com"
            )
        try:
            from groq import Groq
        except ImportError:
            raise ProviderError(
                "groq package is not installed. Run: pip install groq"
            )
        self._client = Groq(api_key=cfg.GROQ_API_KEY)
        self._model = cfg.GROQ_MODEL
        logger.info("GroqClient ready — model: %s", self._model)

    def chat(self, messages, temperature=0.3, max_tokens=1024) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise ProviderError(
                f"Groq API request failed. Check GROQ_API_KEY and network. Error: {exc}"
            ) from exc

    def stream(self, messages, temperature=0.3, max_tokens=1024) -> Iterator[str]:
        try:
            stream = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            raise ProviderError(f"Groq streaming failed. Error: {exc}") from exc


# ─── HuggingFace ─────────────────────────────────────────────────────────────

class HuggingFaceClient(LLMClient):
    def __init__(self) -> None:
        cfg = get_settings()
        if not cfg.HF_TOKEN:
            raise ProviderNotConfiguredError(
                "HuggingFace is selected (LLM_PROVIDER=huggingface) but "
                "HF_TOKEN is not set in .env. "
                "Get a token at https://huggingface.co/settings/tokens"
            )
        try:
            from huggingface_hub import InferenceClient
        except ImportError:
            raise ProviderError(
                "huggingface_hub package is not installed. Run: pip install huggingface_hub"
            )
        self._client = InferenceClient(
            model=cfg.HF_MODEL_ID,
            token=cfg.HF_TOKEN,
        )
        self._model = cfg.HF_MODEL_ID
        logger.info("HuggingFaceClient ready — model: %s", self._model)

    def chat(self, messages, temperature=0.3, max_tokens=1024) -> str:
        try:
            response = self._client.chat_completion(
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise ProviderError(
                f"HuggingFace Inference API failed. Check HF_TOKEN and model availability. "
                f"Error: {exc}"
            ) from exc

    def stream(self, messages, temperature=0.3, max_tokens=1024) -> Iterator[str]:
        try:
            stream = self._client.chat_completion(
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            raise ProviderError(f"HuggingFace streaming failed. Error: {exc}") from exc


# ─── Ollama ───────────────────────────────────────────────────────────────────

class OllamaClient(LLMClient):
    """
    Connects to Ollama's OpenAI-compatible endpoint at /v1.
    No extra package needed — uses the same openai SDK as LM Studio.
    Start Ollama first: `ollama serve` and pull a model: `ollama pull llama3.2`
    """
    def __init__(self) -> None:
        cfg = get_settings()
        if not cfg.OLLAMA_BASE_URL:
            raise ProviderNotConfiguredError(
                "Ollama is selected (DA_PROVIDER=ollama) but OLLAMA_BASE_URL is missing."
            )
        try:
            from openai import OpenAI
        except ImportError:
            raise ProviderError("openai package not installed. Run: pip install openai")

        self._model = cfg.OLLAMA_MODEL or self._detect_model(cfg.OLLAMA_BASE_URL)
        # Ollama's /v1 endpoint accepts any non-empty api_key
        self._client = OpenAI(base_url=cfg.OLLAMA_BASE_URL, api_key="ollama")
        logger.info("OllamaClient ready — model: %s", self._model)

    def _detect_model(self, base_url: str) -> str:
        """Auto-detect the first available Ollama model via GET /v1/models."""
        try:
            from openai import OpenAI
            probe = OpenAI(base_url=base_url, api_key="ollama")
            models = probe.models.list()
            if models.data:
                detected = models.data[0].id
                logger.info("Ollama auto-detected model: %s", detected)
                return detected
        except Exception as exc:
            raise ProviderError(
                f"Ollama is selected but could not connect to {base_url}. "
                f"Make sure Ollama is running: run `ollama serve` in a terminal, "
                f"then pull a model: `ollama pull llama3.2`. Error: {exc}"
            ) from exc
        raise ProviderError(
            f"Ollama is running at {base_url} but no models are loaded. "
            "Pull one first: `ollama pull llama3.2`"
        )

    def chat(self, messages, temperature=0.3, max_tokens=1024) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise ProviderError(
                f"Ollama request failed. Is `ollama serve` still running? Error: {exc}"
            ) from exc

    def stream(self, messages, temperature=0.3, max_tokens=1024) -> Iterator[str]:
        try:
            stream = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as exc:
            raise ProviderError(f"Ollama streaming failed. Error: {exc}") from exc

    def name(self) -> str:
        return f"OllamaClient({self._model})"


# ─── None / Stub ─────────────────────────────────────────────────────────────

class StubClient(LLMClient):
    """Used when provider=none. Returns deterministic template responses."""

    def chat(self, messages, temperature=0.3, max_tokens=1024) -> str:
        logger.warning("StubClient: provider=none — returning deterministic response.")
        return json.dumps({
            "prosecution": "No LLM provider configured. This is a stub response.",
            "severity": "REVIEW",
            "key_evidence": [],
            "breach_impact": "Unknown — LLM not configured.",
        })

    def stream(self, messages, temperature=0.3, max_tokens=1024) -> Iterator[str]:
        yield self.chat(messages)


# ─── Factory ──────────────────────────────────────────────────────────────────

def _build_client(provider: "LLMProvider") -> LLMClient:
    """Internal: instantiate a client for a specific provider enum value."""
    from config import LLMProvider
    if provider == LLMProvider.LMSTUDIO:
        return LMStudioClient()
    elif provider == LLMProvider.OLLAMA:
        return OllamaClient()
    elif provider == LLMProvider.GROQ:
        return GroqClient()
    elif provider == LLMProvider.HUGGINGFACE:
        return HuggingFaceClient()
    elif provider == LLMProvider.NONE:
        return StubClient()
    else:
        raise ProviderError(
            f"Unknown provider: '{provider}'. "
            "Valid options: lmstudio, ollama, groq, huggingface, none"
        )


def get_llm_client() -> LLMClient:
    """Returns client for the legacy LLM_PROVIDER key (used by tests/fallback)."""
    cfg = get_settings()
    logger.info("Initialising LLM client for provider: %s", cfg.LLM_PROVIDER)
    return _build_client(cfg.LLM_PROVIDER)


def get_prosecutor_client() -> LLMClient:
    """
    Returns the client for Pass 1 (Prosecutor).
    Configured via PROSECUTOR_PROVIDER in .env (default: lmstudio).
    Raises ProviderError with a clear message if unavailable.
    """
    cfg = get_settings()
    logger.info("Initialising Prosecutor client: %s", cfg.PROSECUTOR_PROVIDER)
    return _build_client(cfg.PROSECUTOR_PROVIDER)


def get_da_client() -> LLMClient:
    """
    Returns the client for Pass 2 (Devil's Advocate).
    Configured via DA_PROVIDER in .env (default: ollama).
    Raises ProviderError with a clear message if unavailable.
    """
    cfg = get_settings()
    logger.info("Initialising Devil's Advocate client: %s", cfg.DA_PROVIDER)
    return _build_client(cfg.DA_PROVIDER)
