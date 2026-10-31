"""
backend/security/sanitize.py — Input & Output Sanitizer for LLM Gateways.

Guarantees:
1. Unicode NFKC normalization.
2. Stripping of zero-width and bidirectional control characters.
3. Stripping of markdown images, URLs, and HTML tags (exfiltration prevention).
4. Collapsing whitespace and length truncation.
5. Escaping of template interpolation characters.
"""
from __future__ import annotations

import re
import unicodedata

# Zero-width spaces, directional overrides, and invisible joiners
ZERO_WIDTH_AND_BIDI_PATTERN = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF\u00AD]"
)

# Markdown images and URLs
MARKDOWN_IMAGE_PATTERN = re.compile(r"!\[.*?\]\(.*?\)")
URL_PATTERN = re.compile(r"(https?://\S+|ftp://\S+|file://\S+)")
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


def sanitize_text(text: str | None, max_length: int = 240) -> str:
    """
    Sanitizes untrusted strings before prompt injection or UI rendering.
    """
    if not text:
        return ""

    # 1. Unicode NFKC Normalization
    normalized = unicodedata.normalize("NFKC", str(text))

    # 2. Strip Zero-Width & BiDi Overrides
    cleaned = ZERO_WIDTH_AND_BIDI_PATTERN.sub("", normalized)

    # 3. Strip Markdown Images & HTML Tags
    cleaned = MARKDOWN_IMAGE_PATTERN.sub("[IMAGE_REMOVED]", cleaned)
    cleaned = HTML_TAG_PATTERN.sub(" ", cleaned)

    # 4. Strip Raw URLs
    cleaned = URL_PATTERN.sub("[URL_REMOVED]", cleaned)

    # 5. Escape template braces to prevent format string injection
    cleaned = cleaned.replace("{", "{{").replace("}", "}}")

    # 6. Collapse Whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    # 7. Length Capping
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "…"

    return cleaned


def sanitize_output_narrative(narrative_text: str) -> str:
    """
    Post-processes model output narratives to strip unauthorized markdown links,
    embedded images, and potential data-exfiltration payloads.
    """
    if not narrative_text:
        return ""
    # Strip markdown images entirely
    clean = MARKDOWN_IMAGE_PATTERN.sub("", narrative_text)
    # Strip raw external URLs from narrative
    clean = URL_PATTERN.sub("[LINK_SUPPRESSED]", clean)
    # Strip html
    clean = HTML_TAG_PATTERN.sub("", clean)
    return clean.strip()
