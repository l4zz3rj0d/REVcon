import re
from typing import List, Dict, Any

class StringIntelligence:
    """Extracts ASCII and Wide (UTF-16) strings and groups them into categories."""

    def __init__(self, filepath: str, min_len: int = 4):
        self.filepath = filepath
        self.min_len = min_len

    def analyze(self) -> Dict[str, Any]:
        """Extracts and categorizes strings."""
        extracted = self._extract_strings()
        categorized = self._categorize_strings(extracted)

        return {
            "raw_count": len(extracted),
            "all_strings": extracted,
            "categories": categorized
        }

    def _extract_strings(self) -> List[str]:
        """Extracts ASCII and UTF-16LE strings using fast regex operations on bytes."""
        strings = []
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()

            # 1. Extract ASCII strings
            ascii_re = re.compile(rb"[ -~]{" + str(self.min_len).encode() + rb",}")
            for match in ascii_re.finditer(data):
                strings.append(match.group().decode("ascii", errors="ignore"))

            # 2. Extract UTF-16LE strings (wide strings)
            utf16_re = re.compile(rb"(?:[ -~]\x00){" + str(self.min_len).encode() + rb",}")
            for match in utf16_re.finditer(data):
                strings.append(match.group().decode("utf-16le", errors="ignore"))

        except Exception:
            pass
        return list(set(strings))

    def _categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Groups strings into categories based on regex matching and keyword scoring."""
        categories = {
            "flag_indicators": [],
            "error_messages": [],
            "success_messages": [],
            "passwords": [],
            "urls": [],
            "ips": [],
            "file_paths": [],
            "registry_keys": [],
            "commands": []
        }

        # Regex patterns
        flag_pattern = re.compile(r'\b[a-zA-Z0-9_\-]{3,}\{[a-zA-Z0-9_\-\+\?\!\.\@\#\*]+?\}', re.IGNORECASE)
        url_pattern = re.compile(r'https?://[a-zA-Z0-9\-\.\/\?=&_%#\+]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        # Win/Unix paths
        file_path_pattern = re.compile(r'(?:[a-zA-Z]:\\(?:[a-zA-Z0-9_\-]+\\)*[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]{2,4})|(?:\/(?:[a-zA-Z0-9_\-]+\/)+[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]{2,4})')
        
        # Registry Keys
        registry_pattern = re.compile(r'\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU)\\[a-zA-Z0-9_\-\\]+', re.IGNORECASE)

        # Commands/Executables
        commands_pattern = re.compile(r'\b(?:cmd\.exe|powershell\.exe|/bin/sh|/bin/bash|chmod|systemctl|wget|curl)\b', re.IGNORECASE)

        # Keywords
        err_kws = ["error", "fail", "invalid", "incorrect", "wrong", "exception", "crash", "panic", "denied", "forbidden"]
        success_kws = ["success", "correct", "solved", "congrats", "congratulations", "granted", "win", "passed", "valid"]
        pwd_kws = ["password", "passwd", "secret", "private_key", "apikey", "api_key", "auth_token"]

        for s in strings:
            s_strip = s.strip()
            if not s_strip:
                continue

            s_lower = s_strip.lower()

            # Flag Indicators
            if flag_pattern.search(s_strip) or any(f in s_lower for f in ["flag{", "ctf{", "htb{", "picoctf{"]):
                categories["flag_indicators"].append(s_strip)
                continue

            # URLs
            if url_pattern.search(s_strip):
                categories["urls"].append(s_strip)
                continue

            # IP Addresses
            if ip_pattern.search(s_strip):
                categories["ips"].append(s_strip)
                continue

            # File Paths
            if file_path_pattern.search(s_strip):
                categories["file_paths"].append(s_strip)
                continue

            # Registry Keys
            if registry_pattern.search(s_strip):
                categories["registry_keys"].append(s_strip)
                continue

            # Commands
            if commands_pattern.search(s_strip) or s_lower.startswith("sudo ") or s_lower.startswith("run "):
                categories["commands"].append(s_strip)
                continue

            # Success Messages
            if any(kw in s_lower for kw in success_kws):
                if len(s_strip) < 100:
                    categories["success_messages"].append(s_strip)
                continue

            # Error Messages
            if any(kw in s_lower for kw in err_kws):
                if len(s_strip) < 100:
                    categories["error_messages"].append(s_strip)
                continue

            # Passwords/Secrets
            if any(kw in s_lower for kw in pwd_kws):
                # Avoid long text strings matching keyword
                if len(s_strip) < 40 and not any(kw in s_lower for kw in ["enter", "type", "invalid", "wrong"]):
                    categories["passwords"].append(s_strip)

        # De-duplicate and sort
        for cat in categories:
            categories[cat] = sorted(list(set(categories[cat])))

        return categories
