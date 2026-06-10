from typing import Dict, Any
from revcon.plugins.base import BasePlugin

class CryptoDetectorPlugin(BasePlugin):
    """Detects cryptographic signatures, algorithms, and imports."""

    @property
    def name(self) -> str:
        return "Crypto Detector"

    @property
    def description(self) -> str:
        return "Scans for crypto constants, imports, and keywords."

    def run(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        heuristics = metadata.get("heuristics", {})
        imports = metadata.get("imports", {})
        symbols = metadata.get("symbols", {})

        # Check for crypto constants detected by Capstone
        crypto_sigs = heuristics.get("crypto_signatures", [])
        if crypto_sigs:
            findings.append(f"Cryptographic constants detected in code segment: {', '.join(crypto_sigs)}")

        # Check imports for crypto libraries (openssl, crypt32, etc.)
        all_imports = imports.get("all_imports", [])
        crypto_imports = [imp for imp in all_imports if any(k in imp.lower() for k in ["crypt", "ssl", "aes", "sha", "md5", "hash"])]
        if crypto_imports:
            findings.append(f"Imported crypto-related APIs: {', '.join(crypto_imports[:10])}")

        # Check symbols for crypto names
        all_symbols = symbols.get("all_symbols", [])
        crypto_symbols = [sym for sym in all_symbols if any(k in sym.lower() for k in ["crypt", "aes", "sha", "md5", "hash", "cipher"])]
        if crypto_symbols:
            findings.append(f"Found {len(crypto_symbols)} cryptography-related function symbols.")

        return {
            "detected": len(findings) > 0,
            "findings": findings
        }
