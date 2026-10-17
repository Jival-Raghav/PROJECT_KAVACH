"""backend/resolve/normalize.py
Normalization functions for identity resolution.
Handles NFKD accent stripping, punctuation cleaning, Last, First inversion,
email local-part extraction, trailing digit variant stripping, nickname expansion,
and name tokenization.
"""
from __future__ import annotations

import re
import unicodedata


# ─── Nickname Dictionary (Bidirectional) ──────────────────────────────────────
NICKNAME_GROUPS = [
    {"robert", "bob", "bobby", "rob", "robbie"},
    {"william", "bill", "billy", "will", "willy", "liam"},
    {"james", "jim", "jimmy", "jamie"},
    {"michael", "mike", "mikey"},
    {"richard", "dick", "rick", "rich", "richie"},
    {"charles", "charlie", "chuck"},
    {"joseph", "joe", "joey"},
    {"thomas", "tom", "tommy"},
    {"christopher", "chris"},
    {"daniel", "dan", "danny"},
    {"david", "dave", "davy"},
    {"alexander", "alex", "alec"},
    {"anthony", "tony"},
    {"andrew", "andy", "drew"},
    {"benjamin", "ben", "benny"},
    {"edward", "ed", "eddie", "ted"},
    {"elizabeth", "beth", "liz", "lizzie", "eliza"},
    {"jennifer", "jen", "jenny"},
    {"katherine", "kate", "kathy", "katie"},
    {"margaret", "maggie", "peggy"},
    {"patricia", "pat", "patty", "trish"},
    {"steven", "stephen", "steve"},
]

# Map each nickname/name to its canonical group
NICKNAME_MAP: dict[str, set[str]] = {}
for group in NICKNAME_GROUPS:
    for name in group:
        NICKNAME_MAP[name] = group


def strip_accents(text: str) -> str:
    """Strip diacritics and accents using Unicode NFKD normalization (e.g. Müller -> Muller)."""
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKD", str(text))
    return "".join(c for c in normalized if not unicodedata.combining(c))


def normalize_name(raw_name: str) -> str:
    """Clean and normalize a human name:
    - Lowercases & strips accents
    - Converts 'Last, First' to 'First Last'
    - Removes non-alphanumeric punctuation (retains spaces and hyphens)
    - Collapses whitespace
    """
    if not raw_name:
        return ""

    s = strip_accents(str(raw_name)).strip().lower()

    # Handle 'Last, First'
    if "," in s:
        parts = s.split(",", 1)
        last = parts[0].strip()
        first = parts[1].strip()
        s = f"{first} {last}".strip()

    # Remove special punctuation
    s = re.sub(r"[^\w\s-]", "", s)
    # Collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    return s


def extract_email_local_part(email_or_user: str) -> str:
    """Extract and normalize the local username portion from an email or domain string:
    - 'john.doe@company.corp' -> 'john.doe'
    - 'CORP\\john.doe' -> 'john.doe'
    """
    if not email_or_user:
        return ""
    s = strip_accents(str(email_or_user)).strip().lower()
    if "@" in s:
        s = s.split("@")[0]
    if "\\" in s:
        s = s.split("\\")[-1]
    return s


def strip_trailing_digits(identifier: str) -> str:
    """Strip versioning or collision digit suffixes:
    - 'jraghav2' -> 'jraghav'
    - 'asmith01' -> 'asmith'
    Preserves purely numeric identifiers (e.g. '10042').
    """
    if not identifier:
        return ""
    s = str(identifier).strip()
    # Don't strip if identifier is entirely numbers
    if s.isdigit():
        return s
    match = re.match(r"^([a-zA-Z_.-]+)\d+$", s)
    if match and len(match.group(1)) >= 3:
        return match.group(1)
    return s


def expand_name_variants(name_token: str) -> set[str]:
    """Return all known nickname variations for a given name token."""
    t = name_token.lower().strip()
    return NICKNAME_MAP.get(t, {t})


def tokenize_name(name: str) -> list[str]:
    """Tokenize a normalized name into component words."""
    norm = normalize_name(name)
    if not norm:
        return []
    return [w for w in re.split(r"[\s-]+", norm) if w]


def get_initials_and_surname(name: str) -> tuple[str, str]:
    """Extract first initial and surname:
    - 'John Doe' -> ('j', 'doe')
    - 'Alice Jane Smith' -> ('a', 'smith')
    """
    tokens = tokenize_name(name)
    if not tokens:
        return "", ""
    initial = tokens[0][0] if tokens[0] else ""
    surname = tokens[-1] if len(tokens) > 1 else tokens[0]
    return initial, surname


def derive_name_from_identifier(identifier: str) -> str:
    """Derive a candidate human name from an email local-part or username:
    - 'bob.davis' -> 'bob davis'
    - 'e_montgomery' -> 'e montgomery'
    - 'peggy.hamilton' -> 'peggy hamilton'
    - 'ext_consultant_1' -> 'ext consultant 1'
    """
    if not identifier:
        return ""
    local = extract_email_local_part(identifier)
    # If contains delimiter, preserve segments
    if any(sep in local for sep in (".", "_", "-")):
        parts = re.split(r"[._-]+", local)
        return " ".join(p for p in parts if p).strip()
    return local


