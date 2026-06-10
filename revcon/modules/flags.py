import re
from typing import Dict, Any, List, Optional

class FlagIntelligence:
    """Searches binary strings, symbols, and decoded base64 candidates for flag format matches."""

    def __init__(self, flag_format: str, strings: List[str], symbols: List[str]):
        self.flag_format = flag_format
        self.strings = strings
        self.symbols = symbols
        self.prefix = self._extract_prefix(flag_format)
        self.regex = self._build_regex(flag_format)

    def _extract_prefix(self, fmt: str) -> str:
        """Extracts the prefix before the curly braces. e.g. 'FLAG{}' -> 'FLAG'."""
        idx = fmt.find("{")
        if idx == -1:
            return fmt
        return fmt[:idx]

    def _build_regex(self, fmt: str) -> re.Pattern:
        """Converts a flag format like 'FLAG{}' into a compiled regex: FLAG\\{.*?\\}."""
        idx = fmt.find("{")
        if idx == -1:
            # No braces — treat as a plain prefix search
            return re.compile(re.escape(fmt), re.IGNORECASE)
        prefix = fmt[:idx]
        return re.compile(re.escape(prefix) + r"\{.*?\}", re.IGNORECASE)

    def analyze(self) -> Dict[str, Any]:
        """Scans all string and symbol sources for flag matches."""
        direct_matches: List[str] = []
        partial_matches: List[str] = []

        # Combine all searchable text
        corpus = self.strings + self.symbols

        # Also try to decode base64 candidates in the string pool
        decoded_b64 = self._decode_base64_candidates(self.strings)
        corpus.extend(decoded_b64)

        for entry in corpus:
            # Direct regex match (full flag format)
            if self.regex.search(entry):
                match = self.regex.search(entry)
                if match:
                    direct_matches.append(match.group())
            # Partial match — contains the prefix but not the full format
            elif self.prefix and self.prefix.lower() in entry.lower():
                partial_matches.append(entry)

        # Supplementary partial keyword scan
        partial_keywords = ["flag", "secret", "token", "key", "ctf"]
        for entry in self.strings:
            entry_l = entry.lower()
            for kw in partial_keywords:
                if kw in entry_l and entry not in partial_matches and entry not in direct_matches:
                    if len(entry) < 120:
                        partial_matches.append(entry)
                    break

        # Deduplicate and sort
        direct_matches = sorted(list(set(direct_matches)))
        partial_matches = sorted(list(set(partial_matches)))

        # Confidence
        if direct_matches:
            confidence = "HIGH"
        elif partial_matches:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return {
            "flag_format": self.flag_format,
            "regex": self.regex.pattern,
            "matches": direct_matches,
            "partial_matches": partial_matches[:20],  # Cap at 20 to avoid noise
            "confidence": confidence
        }

    def _decode_base64_candidates(self, strings: List[str]) -> List[str]:
        """Attempts to base64-decode strings that look like valid base64 and returns decoded results."""
        import base64
        decoded = []
        b64_pattern = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')

        for s in strings:
            s_stripped = s.strip()
            if b64_pattern.match(s_stripped):
                try:
                    raw = base64.b64decode(s_stripped, validate=True)
                    text = raw.decode("utf-8", errors="ignore")
                    if text and any(c.isprintable() for c in text):
                        decoded.append(text)
                except Exception:
                    pass
        return decoded
