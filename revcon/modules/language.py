from typing import List, Dict, Tuple

class LanguageDetection:
    """Detects programming language of the binary using symbols and strings with confidence scoring."""

    def __init__(self, symbols: List[str], strings: List[str]):
        self.symbols = symbols
        self.strings = strings

    def detect(self) -> Tuple[str, int]:
        """Detects language and returns (Language, Confidence Percentage)."""
        scores = {
            "Rust": 0,
            "Go": 0,
            "C++": 0,
            "Zig": 0,
            "C": 5  # Baseline score for compiled C binary
        }

        # 1. Analyze Symbols
        for sym in self.symbols:
            sym_l = sym.lower()
            
            # Rust Symbols
            if "rust_begin_unwind" in sym_l:
                scores["Rust"] += 50
            if "rust_eh_personality" in sym_l:
                scores["Rust"] += 30
            if "_zn4core" in sym_l or "core::ops" in sym_l:
                scores["Rust"] += 30
            if "_zn5alloc" in sym_l or "alloc::" in sym_l:
                scores["Rust"] += 30
            if "panic_bounds_check" in sym_l:
                scores["Rust"] += 20

            # Go Symbols
            if "runtime.main" in sym_l:
                scores["Go"] += 50
            if "runtime.go" in sym_l:
                scores["Go"] += 30
            if "go.string" in sym_l:
                scores["Go"] += 30
            if "go.build" in sym_l:
                scores["Go"] += 30

            # C++ Symbols
            if sym.startswith("_ZN") or sym.startswith("__ZN"):
                scores["C++"] += 20
            if "std::" in sym:
                scores["C++"] += 30
            if "__cxa_begin_catch" in sym or "__cxa_throw" in sym:
                scores["C++"] += 30
            if "__gxx_personality" in sym:
                scores["C++"] += 20

            # Zig Symbols
            if "zig_panic" in sym_l:
                scores["Zig"] += 50
            if "zig" in sym_l:
                scores["Zig"] += 10

        # 2. Analyze Strings
        for s in self.strings:
            s_l = s.lower()

            # Rust Strings
            if "rust_backtrace" in s_l:
                scores["Rust"] += 30
            if "rustc" in s_l:
                scores["Rust"] += 15
            if "panic_bounds_check" in s_l:
                scores["Rust"] += 20

            # Go Strings
            if "go build id" in s_l:
                scores["Go"] += 45
            if "go:linkname" in s_l:
                scores["Go"] += 25
            if "runtime.go" in s_l:
                scores["Go"] += 20

            # C++ Strings
            if "libstdc++" in s_l:
                scores["C++"] += 35
            if "glibcxx_" in s:
                scores["C++"] += 25

            # Zig Strings
            if "zig_panic" in s_l:
                scores["Zig"] += 35
            if "zig-cache" in s_l:
                scores["Zig"] += 25

        # Find the highest scoring language
        detected_lang = "C"
        max_score = scores["C"]

        for lang, score in scores.items():
            if score > max_score:
                max_score = score
                detected_lang = lang

        # Compute confidence level
        if detected_lang == "C":
            # If no other indicators match, C is a safe bet but with low confidence if binary has no symbols
            confidence = 80 if len(self.symbols) > 0 else 50
        else:
            # Bound confidence between 60% and 99%
            confidence = min(99, 60 + int((max_score / (max_score + 100)) * 39))

        return detected_lang, confidence
