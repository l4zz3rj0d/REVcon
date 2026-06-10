import json
import sys
from typing import Dict, Any, List
from revcon.banner import C, _no_color, _strip

class ReportGenerator:
    """Formats and prints binary reconnaissance findings using the Attack Surface methodology."""

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
        """Renders the Attack Surface Discovery report."""
        nc = self._nc

        intel = self.metadata.get("binary_intel", {})
        lang = self.metadata.get("language", {})
        sec = self.metadata.get("security", {})
        heuristics = self.metadata.get("heuristics", {})
        entropy = self.metadata.get("entropy", {})
        imports = self.metadata.get("imports", {})
        strings = self.metadata.get("strings", {})
        runtime = self.metadata.get("runtime_tracer", {})
        payload = self.metadata.get("runtime_payload", {})
        ranked_functions = self.metadata.get("ranked_functions", [])

        if nc:
            print(f"\n  {'='*60}")
            print(f"   REVERSE ENGINEERING ATTACK SURFACE")
            print(f"  {'='*60}")
        else:
            print(f"\n  {C.R}{C.B}{'='*60}{C.RST}")
            print(f"  {C.R}{C.B} REVERSE ENGINEERING ATTACK SURFACE{C.RST}")
            print(f"  {C.R}{C.B}{'='*60}{C.RST}")

        # ── 1. Binary Surface ─────────────────────────────────────────
        self._section("Binary Surface", orbital=True)
        self._row("Type", intel.get('format', 'Unknown'))
        self._row("Architecture", f"{intel.get('arch', 'Unknown')} ({intel.get('bitness', 'Unknown')})")
        self._row("Language", lang.get('language', 'Unknown'))
        self._row("Compiler", intel.get('compiler', 'Unknown'))
        
        prots = [k for k, v in sec.items() if v.get("enabled")]
        self._row("Protections", ", ".join(prots) if prots else "None")

        # ── 2. Code Surface ───────────────────────────────────────────
        if ranked_functions:
            self._section("Code Surface", orbital=True)
            self._row("Total Functions", str(len(ranked_functions)))
            # The top suspicious functions will be printed later in the ranked list
            
        # ── 3. String Surface ─────────────────────────────────────────
        categories = strings.get("categories", {})
        has_strings = any(len(lst) > 0 for lst in categories.values())
        if has_strings:
            self._section("String Surface", orbital=True)
            for cat_name, lst in categories.items():
                if lst:
                    title = cat_name.replace("_", " ").title()
                    if nc:
                        print(f"    [{title}]")
                        for s in lst[:3]:
                            print(f"      \u2022 {s}")
                    else:
                        print(f"  {C.R}\u25cf{C.RST} {C.W}{title}{C.RST}")
                        for s in lst[:3]:
                            print(f"    {C.GR}\u2514\u2500{C.RST} {C.G}{s}{C.RST}")

        # ── 4. Import Surface ─────────────────────────────────────────
        flagged_imports = imports.get("flagged_imports", {})
        if flagged_imports:
            self._section("Import Surface", orbital=True)
            for imp_name, desc in list(flagged_imports.items())[:5]:
                if nc:
                    print(f"    {imp_name:<15} \u2192 {desc}")
                else:
                    print(f"  {C.Y}\u25cf{C.RST} {C.Y}{imp_name:<15}{C.RST} {C.GR}\u2192{C.RST} {C.W}{desc}{C.RST}")

        # ── 5. Runtime Surface ────────────────────────────────────────
        if runtime:
            self._section("Runtime Surface", orbital=True)
            self._row("Dynamic Loading", "Yes" if runtime.get("ltrace", {}).get("events") else "No")
            self._row("Executable Memory", "Yes" if payload.get("hidden_payload_detected") else "No")
            
        # ── 6. Validation Surface ─────────────────────────────────────
        self._section("Validation Surface", orbital=True)
        char_val = heuristics.get("per_character_validation", False)
        self._row("Per-Char Loops", "Detected" if char_val else "Not Detected", value_colour=C.R if char_val else C.G)
        self._row("Validation Routines", "Detected" if heuristics.get("validators") else "Not Detected", value_colour=C.R if heuristics.get("validators") else C.G)

        # ── 7. Crypto Surface ─────────────────────────────────────────
        crypto = heuristics.get("crypto_signatures", [])
        if crypto or heuristics.get("base64_detected"):
            self._section("Crypto Surface", orbital=True)
            if crypto:
                self._row("Algorithms", ", ".join(crypto))
            if heuristics.get("base64_detected"):
                self._row("Encoding", "Base64 Routine Detected")
        
        # ── 8. Network Surface ────────────────────────────────────────
        net_str = categories.get("urls", []) + categories.get("ips", [])
        if net_str:
            self._section("Network Surface", orbital=True)
            if categories.get("domains"):
                self._row("Domains", ", ".join(categories["domains"][:2]))
            if categories.get("urls"):
                self._row("URLs", ", ".join(categories["urls"][:2]))
                
        # ── 9. Anti-Analysis Surface ──────────────────────────────────
        anti_debug = False
        for e in runtime.get("strace", {}).get("events", []):
            if e["type"] == "ptrace":
                anti_debug = True
                break
        
        if anti_debug or "ptrace" in flagged_imports:
            self._section("Anti-Analysis Surface", orbital=True)
            self._row("Debugger Detection", "Present (ptrace)", value_colour=C.R)

        # ── 10. Hooking Surface ───────────────────────────────────────
        # Minimal hooking surface for now, based on heuristics
        if heuristics.get("function_dispatch_table"):
            self._section("Hooking Surface", orbital=True)
            self._row("Dynamic Dispatch", "Detected", value_colour=C.R)

        # ── 11. Obfuscation Surface ───────────────────────────────────
        packed = heuristics.get("packed_binary", False)
        xor = heuristics.get("xor_loops_detected", False)
        if packed or xor or payload.get("hidden_payload_detected"):
            self._section("Obfuscation Surface", orbital=True)
            if payload.get("hidden_payload_detected"):
                self._row("Runtime Unpacking", "Suspected (High Confidence)", value_colour=C.R)
            elif packed:
                self._row("Packing", "Detected", value_colour=C.R)
            if xor:
                self._row("XOR Obfuscation", "Detected", value_colour=C.O)

        # ── Top Suspicious Functions ──────────────────────────────────
        if ranked_functions:
            self._section("Top Suspicious Functions", orbital=True)
            for i, func in enumerate(ranked_functions[:5], 1):
                name = func["name"]
                score = func["score"]
                reasons = ", ".join(func["reasons"])
                if nc:
                    print(f"    #{i} {name}")
                    print(f"      Score: {score}")
                    print(f"      Reason: {reasons}")
                else:
                    print(f"  {C.R}#{i} {C.B}{name}{C.RST}")
                    print(f"    {C.GR}\u251c\u2500{C.RST} Score: {C.O}{score}{C.RST}")
                    print(f"    {C.GR}\u2514\u2500{C.RST} Reason: {C.W}{reasons}{C.RST}\n")

        # ── Universal Flag Intelligence ───────────────────────────────
        flag_intel = self.metadata.get("flag_intel")
        if flag_intel:
            self._section("Universal Flag Intelligence", orbital=True)
            matches = flag_intel.get("matches", [])
            partials = flag_intel.get("partial_matches", [])
            if matches:
                self._row("Direct Matches", str(len(matches)), value_colour=C.G)
                for m in matches:
                    if nc:
                        print(f"      {m}")
                    else:
                        print(f"    {C.G}\u25b8{C.RST} {C.G}{m}{C.RST}")
            if partials:
                self._row("Partial Matches", str(len(partials)), value_colour=C.Y)

        # ── Investigation Roadmap ─────────────────────────────────────
        roadmap = self.metadata.get("roadmap", [])
        if roadmap:
            if nc:
                print(f"\n  === Investigation Priority ===")
            else:
                print(f"\n  {C.G}{C.B}=== Investigation Priority ==={C.RST}")
            for step in roadmap:
                if nc:
                    print(f"  {step}")
                else:
                    print(f"  {C.W}{step}{C.RST}")
            print()
