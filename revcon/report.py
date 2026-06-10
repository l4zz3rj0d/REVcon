import json
import sys
from typing import Dict, Any, List
from revcon.banner import C, _no_color, _strip

class ReportGenerator:
    """Formats and prints binary reconnaissance findings to the terminal or exports to JSON."""

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata
        self._nc = _no_color()

    def render_json(self) -> None:
        """Prints the entire metadata structure as raw JSON."""
        print(json.dumps(self.metadata, indent=4))

    # ── section / row helpers (Spider-style) ──────────────────────────

    def _section(self, title: str, orbital: bool = False) -> None:
        if self._nc:
            print(f"\n  [ {title} ]")
            return
        icon = f"{C.R}\u25d3{C.RST} " if orbital else ""
        print(f"\n  {icon}{C.B}{C.W}{title}{C.RST}")
        print(f"  {C.GR}{'\u2500' * 60}{C.RST}")

    def _row(self, label: str, value: str, value_colour=None) -> None:
        vc = value_colour or C.W
        if self._nc:
            print(f"    {label:<20}  {_strip(value)}")
        else:
            print(f"  {C.R}\u25cf{C.RST} {C.W}{label:<18}{C.RST} {vc}{value}{C.RST}")

    def _finding(self, tag: str, severity: str, msg: str) -> None:
        if self._nc:
            print(f"  [{severity:<7}] [{tag}] {msg}")
            return
        sev = severity.upper()
        if "HIGH" in sev or "CRITICAL" in sev:
            bg = C.R
        elif "MEDIUM" in sev:
            bg = C.O
        else:
            bg = C.GR
        print(f"  {bg}{C.B}[{sev:^8}]{C.RST} {C.B}{C.W}{tag:^12}{C.RST} {C.GR}\u2504{C.RST} {C.DIM}{msg}{C.RST}")

    # ── main terminal render ──────────────────────────────────────────

    def render_terminal(self) -> None:
        """Renders a Spider-style CLI report with sections and orbital HUD rows."""
        nc = self._nc

        intel = self.metadata.get("binary_intel", {})
        lang = self.metadata.get("language", {})
        predicted = self.metadata.get("predicted_challenge", {})

        # ── target metadata ───────────────────────────────────────────
        self._section("TARGET METADATA", orbital=True)
        self._row("File Size", f"{intel.get('file_size', 0)} bytes")
        self._row("Format", intel.get('format', 'Unknown'), value_colour=C.G)
        self._row("Architecture", f"{intel.get('arch', 'Unknown')} ({intel.get('bitness', 'Unknown')})")
        self._row("Endianness", intel.get('endianness', 'Unknown'))
        self._row("Compiler", intel.get('compiler', 'Unknown'))
        self._row("Build Info", intel.get('build_info', 'Unknown'))
        self._row("Language", f"{lang.get('language', 'Unknown')} ({lang.get('confidence', 0)}%)", value_colour=C.Y)
        self._row("Challenge Type", f"{predicted.get('type', 'Unknown')} ({predicted.get('confidence', 0)}%)", value_colour=C.MG)

        # ── security mitigations ──────────────────────────────────────
        sec = self.metadata.get("security", {})
        if sec:
            self._section("SECURITY MITIGATIONS", orbital=True)
            for mitigation, details in sec.items():
                status = details.get("status", "Unknown")
                enabled = details.get("enabled", False)
                explanation = details.get("explanation", "")

                if "enabled" in status.lower() or "found" in status.lower() or "full" in status.lower():
                    sc = C.G
                elif "disabled" in status.lower() or "no " in status.lower():
                    sc = C.R
                elif "partial" in status.lower():
                    sc = C.Y
                else:
                    sc = C.W

                if nc:
                    print(f"    {mitigation:<8}: {status:<30}")
                    print(f"      \u2514\u2500 {explanation}")
                else:
                    print(f"  {sc}\u25cf{C.RST} {C.W}{mitigation:<8}{C.RST}  {sc}{status:<30}{C.RST}")
                    print(f"    {C.GR}\u2514\u2500 {explanation}{C.RST}")

        # ── heuristics ────────────────────────────────────────────────
        heuristics = self.metadata.get("heuristics", {})
        self._section("REVERSE ENGINEERING HEURISTICS", orbital=True)

        length = heuristics.get("expected_input_length")
        self._row("Input Length", str(length) if length else "None detected",
                  value_colour=C.G if length else C.GR)

        char_val = heuristics.get("per_character_validation", False)
        self._row("Per-Char Validation", "Yes (character-by-character loops)" if char_val else "No",
                  value_colour=C.G if char_val else C.GR)

        dispatch = heuristics.get("function_dispatch_table", False)
        self._row("Function Dispatch", "Yes (dispatch tables / dynamic jumps)" if dispatch else "No",
                  value_colour=C.Y if dispatch else C.GR)

        xor = heuristics.get("xor_loops_detected", False)
        self._row("XOR Loops", "Yes (XOR decryption/obfuscation)" if xor else "No",
                  value_colour=C.R if xor else C.GR)

        b64 = heuristics.get("base64_detected", False)
        self._row("Base64 Routine", "Yes (base64 character map present)" if b64 else "No",
                  value_colour=C.G if b64 else C.GR)

        crypto = heuristics.get("crypto_signatures", [])
        self._row("Crypto Algorithms", ", ".join(crypto) if crypto else "None",
                  value_colour=C.Y if crypto else C.GR)

        packed = heuristics.get("packed_binary", False)
        self._row("Packed Binary", "Yes (UPX / packed indicators)" if packed else "No",
                  value_colour=C.R if packed else C.GR)

        # ── section entropy ───────────────────────────────────────────
        entropy = self.metadata.get("entropy", {})
        sections = entropy.get("sections", [])
        if sections:
            self._section("SECTION ENTROPY", orbital=True)
            if nc:
                print(f"    {'Section':<15} {'Size (Bytes)':<15} {'Entropy':<10} {'Status':<30}")
                print(f"    {'-'*15} {'-'*15} {'-'*10} {'-'*30}")
            else:
                print(f"  {C.GR}{'Section':<15} {'Size':<15} {'Entropy':<10} {'Status'}{C.RST}")
                print(f"  {C.GR}{'\u2500'*60}{C.RST}")

            for sec_data in sections:
                ent = sec_data.get("entropy", 0.0)
                status = sec_data.get("status", "")
                name = sec_data.get("name", "Unknown")
                size = sec_data.get("size", 0)

                if ent > 7.2:
                    ec = C.R + C.B
                elif ent > 6.0:
                    ec = C.Y
                else:
                    ec = C.GR

                if nc:
                    print(f"    {name:<15} {size:<15} {ent:<10.4f} {status}")
                else:
                    print(f"  {ec}{name:<15} {size:<15} {ent:<10.4f} {status}{C.RST}")

        # ── imports ───────────────────────────────────────────────────
        imports = self.metadata.get("imports", {})
        flagged_imports = imports.get("flagged_imports", {})
        if flagged_imports:
            self._section("HIGH RELEVANCE IMPORTS", orbital=True)
            for imp_name, desc in flagged_imports.items():
                if nc:
                    print(f"    {imp_name:<12} \u2192 {desc}")
                else:
                    print(f"  {C.Y}\u25cf{C.RST} {C.Y}{imp_name:<12}{C.RST} {C.GR}\u2192{C.RST} {C.W}{desc}{C.RST}")

        # ── symbols ───────────────────────────────────────────────────
        symbols = self.metadata.get("symbols", {})
        hvt = symbols.get("high_value_targets", [])
        if hvt:
            self._section("HIGH VALUE TARGETS", orbital=True)
            for i, target in enumerate(hvt, 1):
                if nc:
                    print(f"    {i}. {target}")
                else:
                    print(f"  {C.G}\u25b8{C.RST} {C.G}{target}{C.RST}")

        # ── categorized strings ───────────────────────────────────────
        strings = self.metadata.get("strings", {})
        categories = strings.get("categories", {})
        has_strings = any(len(lst) > 0 for lst in categories.values())

        if has_strings:
            self._section("INTERESTING STRINGS", orbital=True)
            for cat_name, lst in categories.items():
                if lst:
                    title = cat_name.replace("_", " ").upper()
                    if nc:
                        print(f"    [{title}]")
                    else:
                        print(f"  {C.R}{C.B}[{title}]{C.RST}")
                    for s in lst[:5]:
                        short = s if len(s) < 80 else s[:77] + "..."
                        if nc:
                            print(f"      \u2022 {short}")
                        else:
                            print(f"    {C.GR}\u2514\u2500{C.RST} {C.W}{short}{C.RST}")
                    if len(lst) > 5:
                        if nc:
                            print(f"      ... ({len(lst) - 5} more hidden)")
                        else:
                            print(f"    {C.GR}   ... ({len(lst) - 5} more hidden. Use --verbose to see all){C.RST}")

        # ── plugin findings ───────────────────────────────────────────
        plugin_findings = self.metadata.get("plugin_findings", {})
        has_detections = any(res.get("detected", False) for res in plugin_findings.values())
        if has_detections:
            self._section("PLUGIN DETECTIONS", orbital=True)
            for p_name, res in plugin_findings.items():
                if res.get("detected", False):
                    if nc:
                        print(f"    [{p_name}]")
                    else:
                        print(f"  {C.MG}\u25c8{C.RST} {C.B}{C.W}{p_name}{C.RST}")
                    for finding in res.get("findings", []):
                        if nc:
                            print(f"      - {finding}")
                        else:
                            print(f"    {C.GR}\u2514\u2500{C.RST} {C.W}{finding}{C.RST}")

        # ── flag intelligence ─────────────────────────────────────────
        flag_intel = self.metadata.get("flag_intel")
        if flag_intel:
            self._section("FLAG INTELLIGENCE", orbital=True)
            self._row("Target Format", flag_intel.get("flag_format", "N/A"))
            self._row("Search Regex", flag_intel.get("regex", "N/A"))

            confidence = flag_intel.get("confidence", "LOW")
            conf_colour = C.G if confidence == "HIGH" else C.Y if confidence == "MEDIUM" else C.R
            self._row("Confidence", confidence, value_colour=conf_colour)

            matches = flag_intel.get("matches", [])
            if matches:
                if nc:
                    print(f"    Direct Matches:")
                else:
                    print(f"\n  {C.B}{C.W}Direct Matches:{C.RST}")
                for m in matches:
                    if nc:
                        print(f"      {m}")
                    else:
                        print(f"    {C.G}\u25b8{C.RST} {C.G}{m}{C.RST}")
            else:
                if nc:
                    print(f"    Direct Matches:  None")
                else:
                    print(f"\n  {C.B}{C.W}Direct Matches:{C.RST}  {C.GR}None{C.RST}")

            partials = flag_intel.get("partial_matches", [])
            if partials:
                if nc:
                    print(f"    Partial Matches:")
                else:
                    print(f"  {C.B}{C.W}Partial Matches:{C.RST}")
                for p in partials[:10]:
                    short = p if len(p) < 80 else p[:77] + "..."
                    if nc:
                        print(f"      {short}")
                    else:
                        print(f"    {C.Y}\u25b8{C.RST} {C.Y}{short}{C.RST}")
                if len(partials) > 10:
                    if nc:
                        print(f"      ... ({len(partials) - 10} more hidden)")
                    else:
                        print(f"    {C.GR}... ({len(partials) - 10} more hidden){C.RST}")
            else:
                if nc:
                    print(f"    Partial Matches: None")
                else:
                    print(f"  {C.B}{C.W}Partial Matches:{C.RST} {C.GR}None{C.RST}")

        # ── analyst summary ───────────────────────────────────────────
        guidance = self.metadata.get("analyst_guidance", {})

        if nc:
            print(f"\n  {'='*60}")
            print(f"   ANALYST SUMMARY & RECOMMENDATIONS")
            print(f"  {'='*60}")
        else:
            print(f"\n  {C.Y}{C.B}{'='*60}{C.RST}")
            print(f"  {C.Y}{C.B} ANALYST SUMMARY & RECOMMENDATIONS{C.RST}")
            print(f"  {C.Y}{C.B}{'='*60}{C.RST}")

        self._row("Language", lang.get("language", "Unknown"))
        self._row("Challenge Type", predicted.get("type", "Unknown"))

        if length:
            self._row("Input Length", f"{length} characters")

        if hvt:
            self._row("Primary Targets", ", ".join(hvt[:3]))

        strategies = guidance.get("strategies", [])
        if strategies:
            if nc:
                print(f"\n    Analysis Strategies:")
            else:
                print(f"\n  {C.R}{C.B}Analysis Strategies:{C.RST}")
            for strategy in strategies:
                if nc:
                    print(f"      \u2022 {strategy}")
                else:
                    print(f"    {C.GR}\u2514\u2500{C.RST} {C.W}{strategy}{C.RST}")
        else:
            if nc:
                print(f"\n    \u2022 No special strategies determined for this compiler layout.")
            else:
                print(f"\n    {C.GR}\u2514\u2500 No special strategies determined for this compiler layout.{C.RST}")

        next_step = guidance.get("next_steps", "Open the binary in Ghidra/IDA Pro/Binary Ninja.")
        if nc:
            print(f"\n    Recommended Next Step:")
            print(f"      {next_step}")
        else:
            print(f"\n  {C.G}{C.B}Recommended Next Step:{C.RST}")
            print(f"    {C.B}{C.W}{next_step}{C.RST}")

        if nc:
            print(f"  {'='*60}\n")
        else:
            print(f"  {C.Y}{C.B}{'='*60}{C.RST}\n")
