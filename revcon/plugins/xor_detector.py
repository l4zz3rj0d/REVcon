from typing import Dict, Any
from revcon.plugins.base import BasePlugin

class XORDetectorPlugin(BasePlugin):
    """Detects XOR obfuscation signatures, loops, and potential XOR-encoded strings."""

    @property
    def name(self) -> str:
        return "XOR Detector"

    @property
    def description(self) -> str:
        return "Scans for inline XOR decryption loops and XOR indicators."

    def run(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        heuristics = metadata.get("heuristics", {})
        strings = metadata.get("strings", {})

        # Check if core heuristics engine found a XOR loop
        if heuristics.get("xor_loops_detected", False):
            findings.append("An active assembly loop containing a XOR instruction (potential decryption loop) was detected.")

        # Scan strings for potential xor indicators
        xor_strings = [s for s in strings.get("all_strings", []) if "xor" in s.lower() or "decrypt" in s.lower()]
        if xor_strings:
            findings.append(f"Found {len(xor_strings)} strings containing XOR/decryption keywords.")

        return {
            "detected": len(findings) > 0,
            "findings": findings
        }
