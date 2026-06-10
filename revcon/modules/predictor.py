from typing import Dict, Any, Tuple

class ChallengeTypePredictor:
    """Predicts the likely reverse engineering challenge type based on collected signatures and heuristics."""

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    def predict(self) -> Tuple[str, int]:
        """Calculates candidate challenge type scores and returns the highest (type, confidence)."""
        scores = {
            "Password Check": 0,
            "Crackme": 0,
            "XOR Challenge": 0,
            "Crypto Challenge": 0,
            "Validation Challenge": 0,
            "Packed Binary": 0,
            "License Check": 0
        }

        # Extract data points
        symbols = self.metadata.get("symbols", {})
        strings = self.metadata.get("strings", {})
        imports = self.metadata.get("imports", {})
        heuristics = self.metadata.get("heuristics", {})
        entropy = self.metadata.get("entropy", {})

        # 1. Packed Binary Indicators
        if heuristics.get("packed_binary", False):
            scores["Packed Binary"] += 60
        if entropy.get("has_high_entropy", False):
            scores["Packed Binary"] += 40
        for s in strings.get("all_strings", []):
            if any(p in s.lower() for p in ["packed", "compress", "upx", "themida", "enigma"]):
                scores["Packed Binary"] += 20

        # 2. XOR Challenge Indicators
        if heuristics.get("xor_loops_detected", False):
            scores["XOR Challenge"] += 60
        for s in strings.get("all_strings", []):
            if "xor" in s.lower():
                scores["XOR Challenge"] += 20
        for sym in symbols.get("all_symbols", []):
            if "xor" in sym.lower():
                scores["XOR Challenge"] += 30

        # 3. Crypto Challenge Indicators
        crypto_sigs = heuristics.get("crypto_signatures", [])
        if crypto_sigs:
            scores["Crypto Challenge"] += 40 * len(crypto_sigs)
        for s in strings.get("all_strings", []):
            if any(c in s.lower() for c in ["aes", "sha256", "md5", "rc4", "encrypt", "decrypt"]):
                scores["Crypto Challenge"] += 15
        for sym in symbols.get("all_symbols", []):
            if any(c in sym.lower() for c in ["crypt", "cipher", "hash", "salt", "key"]):
                scores["Crypto Challenge"] += 20

        # 4. Validation Challenge Indicators
        if heuristics.get("per_character_validation", False):
            scores["Validation Challenge"] += 50
        if heuristics.get("expected_input_length") is not None:
            scores["Validation Challenge"] += 20
        if heuristics.get("function_dispatch_table", False):
            scores["Validation Challenge"] += 30
        for sym in symbols.get("all_symbols", []):
            if any(v in sym.lower() for v in ["validate", "verify", "check", "cmp"]):
                scores["Validation Challenge"] += 20

        # 5. Password Check Indicators
        flagged_imps = imports.get("flagged_imports", {})
        if "strcmp" in flagged_imps or "strncmp" in flagged_imps or "memcmp" in flagged_imps:
            scores["Password Check"] += 30
        if strings.get("categories", {}).get("passwords"):
            scores["Password Check"] += 40
        for sym in symbols.get("all_symbols", []):
            if "password" in sym.lower() or "passwd" in sym.lower():
                scores["Password Check"] += 45

        # 6. License Check Indicators
        for s in strings.get("all_strings", []):
            if any(l in s.lower() for l in ["license", "serial", "activate", "registration"]):
                scores["License Check"] += 30
        for sym in symbols.get("all_symbols", []):
            if any(l in sym.lower() for l in ["license", "serial", "activate", "register"]):
                scores["License Check"] += 40

        # 7. Crackme Indicators (general fallback / target indicator)
        if strings.get("categories", {}).get("success_messages") or strings.get("categories", {}).get("error_messages"):
            scores["Crackme"] += 30
        if symbols.get("has_symbols"):
            scores["Crackme"] += 20

        # Determine winner
        winner = "Validation Challenge"
        max_score = 0

        for challenge, score in scores.items():
            if score > max_score:
                max_score = score
                winner = challenge

        # Map score to a reasonable confidence percentage
        if max_score == 0:
            confidence = 50
            winner = "Crackme"
        else:
            confidence = min(98, 60 + int((max_score / (max_score + 100)) * 38))

        return winner, confidence
