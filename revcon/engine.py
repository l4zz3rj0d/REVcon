import os
from typing import Dict, Any, List, Optional
from revcon.modules.binary_intel import BinaryIntelligence
from revcon.modules.strings import StringIntelligence
from revcon.modules.symbols import SymbolIntelligence
from revcon.modules.imports import ImportIntelligence
from revcon.modules.language import LanguageDetection
from revcon.modules.security import SecurityAnalysis
from revcon.modules.heuristics import ReverseEngineeringHeuristics
from revcon.modules.entropy import EntropyAnalysis
from revcon.modules.predictor import ChallengeTypePredictor
from revcon.modules.flags import FlagIntelligence
from revcon.plugins import load_plugins
from revcon.utils import log_verbose

class AnalysisEngine:
    """Core analysis orchestrator that drives all intelligence, heuristics, and plugin checks."""

    def __init__(self, filepath: str, quick: bool = False, verbose: bool = False, flag_format: Optional[str] = None):
        self.filepath = filepath
        self.quick = quick
        self.verbose = verbose
        self.flag_format = flag_format

    def run(self) -> Dict[str, Any]:
        """Runs the analysis pipeline."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Target file not found: {self.filepath}")

        log_verbose(f"Starting analysis on {self.filepath}...", self.verbose)

        # 1. Binary Intelligence
        log_verbose("[*] Running Binary Intelligence...", self.verbose)
        intel_module = BinaryIntelligence(self.filepath)
        binary_intel = intel_module.analyze()

        # 2. String Intelligence
        log_verbose("[*] Extracting Strings...", self.verbose)
        strings_module = StringIntelligence(self.filepath)
        strings_intel = strings_module.analyze()

        # 3. Symbol Intelligence
        log_verbose("[*] Extracting Symbols...", self.verbose)
        symbols_module = SymbolIntelligence(self.filepath, binary_intel["format"])
        symbols_intel = symbols_module.analyze()

        # 4. Import Intelligence
        log_verbose("[*] Analyzing Imports...", self.verbose)
        imports_module = ImportIntelligence(self.filepath, binary_intel["format"])
        imports_intel = imports_module.analyze()

        # 5. Language Detection
        log_verbose("[*] Detecting Compiler/Language...", self.verbose)
        lang_module = LanguageDetection(symbols_intel["all_symbols"], strings_intel["all_strings"])
        detected_lang, lang_confidence = lang_module.detect()

        # 6. Security Mitigation Check
        log_verbose("[*] Analyzing Security Mitigations...", self.verbose)
        sec_module = SecurityAnalysis(self.filepath, binary_intel["format"])
        security_intel = sec_module.analyze()

        # 7. Reverse Engineering Heuristics
        heuristics_intel = {}
        if not self.quick:
            log_verbose("[*] Disassembling & Scanning Heuristics (Capstone)...", self.verbose)
            heuristics_module = ReverseEngineeringHeuristics(
                self.filepath, 
                binary_intel["arch"], 
                binary_intel["bitness"], 
                binary_intel["format"], 
                strings_intel["all_strings"],
                self.verbose
            )
            heuristics_intel = heuristics_module.analyze()
        else:
            log_verbose("[*] Quick mode: Skipping disassembly heuristics.", self.verbose)
            heuristics_intel = {
                "expected_input_length": None,
                "per_character_validation": False,
                "function_dispatch_table": False,
                "xor_loops_detected": False,
                "base64_detected": False,
                "crypto_signatures": [],
                "packed_binary": False
            }

        # 8. Entropy Analysis
        entropy_intel = {}
        if not self.quick:
            log_verbose("[*] Calculating section entropy...", self.verbose)
            entropy_module = EntropyAnalysis(self.filepath, binary_intel["format"])
            entropy_intel = entropy_module.analyze()
        else:
            log_verbose("[*] Quick mode: Skipping entropy calculations.", self.verbose)
            entropy_intel = {
                "sections": [],
                "high_entropy_sections": [],
                "has_high_entropy": False
            }

        # Assemble full metadata for predictor & plugins
        metadata = {
            "binary_intel": binary_intel,
            "strings": strings_intel,
            "symbols": symbols_intel,
            "imports": imports_intel,
            "language": {
                "language": detected_lang,
                "confidence": lang_confidence
            },
            "security": security_intel,
            "heuristics": heuristics_intel,
            "entropy": entropy_intel
        }

        # 9. Challenge Type Predictor
        log_verbose("[*] Running Challenge Type Predictor...", self.verbose)
        predictor = ChallengeTypePredictor(metadata)
        challenge_type, challenge_confidence = predictor.predict()
        metadata["predicted_challenge"] = {
            "type": challenge_type,
            "confidence": challenge_confidence
        }

        # 10. Plugin Architecture
        log_verbose("[*] Running loaded plugins...", self.verbose)
        plugins = load_plugins()
        plugin_results = {}
        for plugin in plugins:
            try:
                log_verbose(f"Executing plugin: {plugin.name}", self.verbose)
                plugin_results[plugin.name] = plugin.run(metadata)
            except Exception as e:
                log_verbose(f"Plugin {plugin.name} failed: {str(e)}", self.verbose)
        
        metadata["plugin_findings"] = plugin_results

        # 11. Flag Intelligence (if format specified)
        if self.flag_format:
            log_verbose(f"[*] Running Flag Intelligence for format: {self.flag_format}", self.verbose)
            flag_module = FlagIntelligence(
                self.flag_format,
                strings_intel.get("all_strings", []),
                symbols_intel.get("all_symbols", [])
            )
            metadata["flag_intel"] = flag_module.analyze()
        else:
            metadata["flag_intel"] = None

        # 12. Generate Analyst Guidance / Next Steps
        metadata["analyst_guidance"] = self._generate_guidance(metadata)

        return metadata

    def _generate_guidance(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generates clear analyst guidance based on all collected data."""
        guidance = {
            "strategies": [],
            "next_steps": "Open the binary in Ghidra/IDA Pro/Binary Ninja."
        }

        lang = metadata["language"]["language"]
        challenge = metadata["predicted_challenge"]["type"]
        symbols = metadata["symbols"]
        imports = metadata["imports"]
        heuristics = metadata["heuristics"]

        # Formulate strategies
        if lang == "Rust":
            guidance["strategies"].append("Rust binaries contain heavy metadata. Filter out 'std::', 'core::', and 'alloc::' functions to locate user-defined modules.")
        elif lang == "Go":
            guidance["strategies"].append("Go binaries use standard calling conventions and keep string structures in memory differently. Use Go-specific scripts in Ghidra/IDA to recover types.")
        elif lang == "C++":
            guidance["strategies"].append("C++ classes use virtual method tables (vtables). Look for class instance allocations and track virtual function calls.")
        elif lang == "Zig":
            guidance["strategies"].append("Zig binaries are statically compiled and often contain panic stack trace details. Examine the main logic loop.")

        if challenge == "Packed Binary":
            guidance["strategies"].append("The binary is likely packed. Run standard unpackers (like UPX -d) or find the Entry Point OEP to dump memory.")
            guidance["next_steps"] = "Attempt to unpack the binary using UPX or dynamic debugger dump before disassembling."
        elif challenge == "XOR Challenge":
            guidance["strategies"].append("XOR encryption detected. Locate the decryption loop and check the XOR key (often an immediate value or cycle byte sequence).")
            guidance["next_steps"] = "Locate the xor assembly loop and extract the encryption key/table."
        elif challenge == "Crypto Challenge":
            guidance["strategies"].append("Standard cryptographic algorithms found. Locate where the encryption keys are initialized or the IV is set.")
            guidance["next_steps"] = "Examine key initialization logic and track inputs to cipher execution."
        elif challenge == "Validation Challenge" or challenge == "Password Check":
            guidance["strategies"].append("Character/Password comparisons detected. Check the comparator instructions and track string validation routines.")

            # Formulate specific next steps based on symbols
            hvt = symbols.get("high_value_targets", [])
            if hvt:
                guidance["next_steps"] = f"Open target in disassembler and analyze the '{hvt[0]}' function."
            else:
                flagged = list(imports.get("flagged_imports", {}).keys())
                if flagged:
                    guidance["next_steps"] = f"Set breakpoints on '{flagged[0]}' or watch input buffer locations."

        return guidance
