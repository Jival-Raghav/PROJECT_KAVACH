"""
backend/security/pseudonymize.py — Identity & PII Pseudonymization for Safe LLM Inference.

Maps names, emails, usernames, and sensitive IP addresses to stable, anonymous tokens
prior to feeding data into LLM prompts. Restores original identifiers upon output rendering.
"""
from __future__ import annotations

import re


class Pseudonymizer:
    def __init__(self):
        self.forward_map: dict[str, str] = {}
        self.reverse_map: dict[str, str] = {}
        self._user_counter = 1
        self._acc_counter = 1
        self._ip_counter = 1

    def register_identity(self, raw_id: str, id_type: str = "USER") -> str:
        """Assigns or retrieves a stable pseudonym token."""
        if not raw_id:
            return ""
        norm = raw_id.strip()
        if norm in self.forward_map:
            return self.forward_map[norm]

        if id_type == "USER":
            pseudo = f"USER_{self._user_counter:04d}"
            self._user_counter += 1
        elif id_type == "ACCOUNT":
            pseudo = f"ACCOUNT_{self._acc_counter:04d}"
            self._acc_counter += 1
        elif id_type == "IP":
            pseudo = f"IP_{self._ip_counter:04d}"
            self._ip_counter += 1
        else:
            pseudo = f"ENTITY_{self._user_counter:04d}"
            self._user_counter += 1

        self.forward_map[norm] = pseudo
        self.reverse_map[pseudo] = norm
        return pseudo

    def pseudonymize_text(self, text: str) -> str:
        """Replaces known PII identifiers with pseudonym tokens."""
        if not text:
            return ""
        result = str(text)
        # Replace longer names first to avoid partial substring collisions
        sorted_pairs = sorted(self.forward_map.items(), key=lambda x: len(x[0]), reverse=True)
        for real_val, pseudo in sorted_pairs:
            if real_val in result:
                result = re.sub(rf"\b{re.escape(real_val)}\b", pseudo, result)
        return result

    def depseudonymize_text(self, text: str) -> str:
        """Restores original identifiers from pseudonym tokens."""
        if not text:
            return ""
        result = str(text)
        for pseudo, real_val in self.reverse_map.items():
            result = result.replace(pseudo, real_val)
        return result
