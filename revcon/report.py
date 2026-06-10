import json
import sys
import os
from typing import Dict, Any, List
from revcon.banner import C, _no_color, _strip

# Boilerplates to skip in reports
BOILERPLATES = {
    "_start", "frame_dummy", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini",
    "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
    "__do_global_ctors_aux", "at_quick_exit", "atexit", "__security_init_cookie",
    "__scrt_common_main_seh", "_DllMainCRTStartup", "pre_c_init", "pre_cpp_init",
    "post_pogo_html", "guard_check_icall", "_guard_dispatch_icall_nop",
    "__cxa_finalize", "__gmon_start__"
}

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

    def _why_this_matters(self, description: str, next_steps: str) -> None:
        """Prints analyst mode guidance for findings."""
        if self._nc:
            print(f"\n  [!] Why This Matters:")
            print(f"      {description}")
            print(f"      Investigate: {next_steps}")
        else:
            print(f"\n  {C.Y}[!] Why This Matters:{C.RST}")
            print(f"      {C.DIM}{description}{C.RST}")
            print(f"      {C.W}Investigate:{C.RST} {C.DIM}{next_steps}{C.RST}")

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
        code_analyzer = self.metadata.get("code_analyzer", {})
        exports = code_analyzer.get("exports", [])

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

        deps = code_analyzer.get("dependencies", [])
        if deps:
            self._row("Dependencies", ", ".join(deps))
            self._why_this_matters(
                "The binary links to external shared libraries. The core execution logic or flags may be contained within these dynamic libraries.",
                "Inspect the dynamic call imports and relationships mapped below."
            )

        # ── 2. Library Intelligence ───────────────────────────────────
        is_lib = intel.get("format") == "ELF" and ".so" in os.path.basename(self.metadata.get("filepath", "")).lower()
        if not is_lib:
            is_lib = intel.get("format") == "PE" and ".dll" in os.path.basename(self.metadata.get("filepath", "")).lower()
        if is_lib:
            self._section("Library Intelligence", orbital=True)
            self._row("Type", "Shared Library / Dynamic Link Library")
            self._row("Total Imports", str(len(imports.get("all_imports", []))))
            non_boilerplate_exports = [e for e in exports if e["name"] not in BOILERPLATES]
            self._row("Total Exports", str(len(non_boilerplate_exports)))
            
            susp_exports = [e["name"] for e in non_boilerplate_exports if e.get("priority") == "High"]
            self._row("Suspicious Exports", ", ".join(susp_exports) if susp_exports else "None")
            self._row("Likely Entry Points", ", ".join([e["name"] for e in non_boilerplate_exports[:5]]) if non_boilerplate_exports else "None")

        # ── 3. Code Surface ───────────────────────────────────────────
        self._section("Code Surface", orbital=True)
        funcs_found = code_analyzer.get("functions_found", len(ranked_functions))
        funcs_analyzed = code_analyzer.get("analyzed_count", len(ranked_functions))
        self._row("Functions Found", str(funcs_found))
        self._row("Functions Analyzed", str(funcs_analyzed))
        self._row("Functions Ranked", str(len(ranked_functions)))

        # ── 4. String Surface ─────────────────────────────────────────
        categories = strings.get("categories", {})
        has_strings = any(len(lst) > 0 for lst in categories.values())
        if has_strings:
            self._section("String Surface", orbital=True)
            for cat_name, lst in categories.items():
                if lst:
                    title = cat_name.replace("_", " ").title()
                    if nc:
                        print(f"  {title}")
                        for s in lst[:3]:
                            print(f"    \u2022 {s}")
                    else:
                        print(f"  {C.R}\u25cf{C.RST} {C.W}{title}{C.RST}")
                        for s in lst[:3]:
                            print(f"    {C.GR}\u2514\u2500{C.RST} {C.G}{s}{C.RST}")

        # ── 5. Import Surface ─────────────────────────────────────────
        flagged_imports = imports.get("flagged_imports", {})
        if flagged_imports:
            self._section("Import Surface", orbital=True)
            for imp_name, desc in list(flagged_imports.items())[:5]:
                if nc:
                    print(f"    {imp_name:<15} \u2192 {desc}")
                else:
                    print(f"  {C.Y}\u25cf{C.RST} {C.Y}{imp_name:<15}{C.RST} {C.GR}\u2192{C.RST} {C.W}{desc}{C.RST}")

        # ── 6. Environment Surface ────────────────────────────────────
        envs = code_analyzer.get("recovered_envs", [])
        if envs:
            self._section("Environment Surface", orbital=True)
            for env in envs:
                self._row("Variable", env["var"])
                self._row("Referenced By", env["func"])
                self._row("Confidence", env["confidence"])
                print()
            self._why_this_matters(
                "The target application queries environment variables, indicating configurable validation routes.",
                "Export these variable names in your shell (e.g. export VAR=1) before running the dynamic trace."
            )

        # ── 7. Runtime Surface ────────────────────────────────────────
        mmap_exec = False
        if runtime:
            for e in runtime.get("strace", {}).get("events", []):
                if "exec" in e["type"]:
                    mmap_exec = True
                    break
            if not mmap_exec:
                for c in runtime.get("ltrace", {}).get("calls", []):
                    raw = c.get("raw", "")
                    if ("mmap" in raw or "mprotect" in raw) and any(x in raw for x in ["0b111", ", 7,", ", 7)", "PROT_EXEC"]):
                        mmap_exec = True
                        break

        if runtime:
            self._section("Runtime Surface", orbital=True)
            has_ltrace = runtime.get("ltrace", {}).get("calls") or runtime.get("ltrace", {}).get("events")
            self._row("Dynamic Loading", "Yes" if has_ltrace else "No")
            self._row("Executable Memory", "Yes" if mmap_exec or payload.get("hidden_payload_detected") else "No", value_colour=C.R if (mmap_exec or payload.get("hidden_payload_detected")) else C.G)

        # ── 8. Runtime Payload Detected ───────────────────────────────
        if payload.get("hidden_payload_detected"):
            self._section("Runtime Payload Detected", orbital=True)
            print(f"  {C.R}Evidence:{C.RST}")
            for ev in payload.get("evidence", []):
                if nc:
                    print(f"  - {ev}")
                else:
                    print(f"    {C.R}\u25cf{C.RST} {C.W}{ev}{C.RST}")
            print()
            self._why_this_matters(
                "mmap or mprotect allocations mapped memory with executable permissions, and memcpy executed writes directly into it.",
                "This strongly points to runtime self-modification or custom packing. Trace memory addresses to capture the unpacked executable stream."
            )

        # ── 9. Validation Surface ─────────────────────────────────────
        char_val = heuristics.get("per_character_validation", False)
        validators_exist = heuristics.get("validators")
        if char_val or validators_exist:
            self._section("Validation Surface", orbital=True)
            self._row("Per-Char Loops", "Detected" if char_val else "Not Detected", value_colour=C.R if char_val else C.G)
            self._row("Validation Routines", "Detected" if validators_exist else "Not Detected", value_colour=C.R if validators_exist else C.G)
            self._why_this_matters(
                "Loops verifying characters/inputs sequentially are present, indicating a character-by-character validation scheme.",
                "Target the comparative instructions (cmp, test, sub) inside these loops under a debugger."
            )

        # ── 10. Crypto Surface ────────────────────────────────────────
        crypto = heuristics.get("crypto_signatures", [])
        if crypto or heuristics.get("base64_detected"):
            self._section("Crypto Surface", orbital=True)
            if crypto:
                self._row("Algorithms", ", ".join(crypto))
            if heuristics.get("base64_detected"):
                self._row("Encoding", "Base64 Routine Detected")
            self._why_this_matters(
                "Standard cryptographic constants or encoding layouts were located.",
                "Determine if the keys are loaded statically or derived dynamically through custom initialization."
            )

        # ── 11. Suspicious Constant Recovery ──────────────────────────
        reconstructed_buffers = self.metadata.get("emulation", {}).get("reconstructed_buffers", [])
        if reconstructed_buffers:
            self._section("Suspicious Constant Recovery", orbital=True)
            
            # Prioritize Stack Strings and strings containing interesting keywords
            def priority_key(item):
                val = item.get("ascii", "").lower()
                is_interesting = any(k in val for k in ["flag", "sat", "key", "pass", "env", "prod", "secret", "auth"])
                is_stack = item.get("type") == "Stack String"
                # Return score where smaller is higher priority
                if is_stack and is_interesting: return 0
                if is_stack: return 1
                if is_interesting: return 2
                return 3
            
            sorted_buffers = sorted(reconstructed_buffers, key=priority_key)
            
            for item in sorted_buffers[:10]:
                self._row("Type", item["type"])
                self._row("Value", item["ascii"])
                if "start_addr" in item:
                    self._row("Address", item["start_addr"])
                if "key" in item:
                    self._row("Key", item["key"])
                print()
            self._why_this_matters(
                "Static obfuscation constants, XOR/ADD/SUB runs, or stack-constructed strings were resolved.",
                "Analyze how these recovered buffers are mapped against dynamic comparisons or decryption APIs."
            )

        # ── 12. Anti-Analysis Surface ─────────────────────────────────
        anti_debug = False
        for e in runtime.get("strace", {}).get("events", []):
            if e["type"] == "ptrace":
                anti_debug = True
                break
        
        if anti_debug or "ptrace" in flagged_imports:
            self._section("Anti-Analysis Surface", orbital=True)
            self._row("Debugger Detection", "Present (ptrace)", value_colour=C.R)
            self._why_this_matters(
                "The binary executes ptrace or debugger-detecting library calls to block analysis.",
                "Set hardware breakpoints or patch the call outcomes to bypass debugger exit routines."
            )

        # ── Relationship Surface ──────────────────────────────────────
        self._section("Relationship Surface", orbital=True)
        filename = os.path.basename(self.metadata.get("filepath", ""))
        for dep in code_analyzer.get("dependencies", []):
            if nc:
                print(f"  {filename}\n  └─ imports {dep}")
            else:
                print(f"  {C.B}{filename}{C.RST}\n  {C.GR}\u2514\u2500 imports {C.RST}{C.Y}{dep}{C.RST}")
                
        non_boilerplate_exports = [e for e in exports if e["name"] not in BOILERPLATES]
        for exp in non_boilerplate_exports:
            if nc:
                print(f"  {filename}\n  └─ exports {exp['name']}")
            else:
                print(f"  {C.B}{filename}{C.RST}\n  {C.GR}\u2514\u2500 exports {C.RST}{C.G}{exp['name']}{C.RST}")

        # ── Top Call Paths (Filtered Call Graph) ──────────────────────
        call_graph = code_analyzer.get("call_graph", {})
        if call_graph:
            self._section("Top Call Paths", orbital=True)
            # Prioritize start nodes containing main or exports
            start_nodes = []
            for f in code_analyzer.get("functions", []):
                name = f["name"]
                if name in call_graph and name not in start_nodes and name not in BOILERPLATES:
                    start_nodes.append(name)
            
            start_nodes.sort(key=lambda x: 0 if x in ("main", "send_satellite_message") else 1)
            
            printed = 0
            def print_tree(node, depth=0, local_visited=None):
                if local_visited is None:
                    local_visited = set()
                if node in local_visited or depth > 3 or node in BOILERPLATES:
                    return
                local_visited.add(node)
                indent = "  " * depth
                branch = "└─ " if depth > 0 else ""
                
                color = C.B + C.W if depth == 0 else C.W
                if nc:
                    print(f"    {indent}{branch}{node}")
                else:
                    print(f"    {C.GR}{indent}{branch}{C.RST}{color}{node}{C.RST}")
                    
                for child in call_graph.get(node, []):
                    print_tree(child, depth + 1, local_visited.copy())

            for node in start_nodes:
                if printed >= 3:
                    break
                print_tree(node)
                print()
                printed += 1

        # ── Top Interesting Functions ─────────────────────────────────
        if ranked_functions:
            self._section("Top Interesting Functions", orbital=True)
            for func in ranked_functions[:5]:
                name = func["name"]
                score = func["score"]
                reasons = func.get("reasons", [])
                
                if nc:
                    print(f"  Function:\n  {name}\n\n  Score:\n  {score}\n\n  Reason:")
                    for r in reasons:
                        print(f"  {r}")
                    print()
                else:
                    print(f"  {C.W}Function:{C.RST}\n  {C.B}{name}{C.RST}\n")
                    print(f"  {C.W}Score:{C.RST}\n  {C.O}{score}{C.RST}\n")
                    print(f"  {C.W}Reason:{C.RST}")
                    for r in reasons:
                        print(f"  {C.GR}\u25cf{C.RST} {C.W}{r}{C.RST}")
                    print()

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

        # ── Attack Surface Score ──────────────────────────────────────
        self._section("Attack Surface Score", orbital=True)
        score_binary = 6 if code_analyzer.get("dependencies") else 4
        score_string = min(10, 1 + len(categories.get("passwords", [])) + len(categories.get("urls", [])))
        score_import = min(10, len(flagged_imports) * 2) if flagged_imports else 2
        score_runtime = 9 if (payload.get("hidden_payload_detected") or mmap_exec) else (5 if runtime else 1)
        score_hooking = 8 if heuristics.get("function_dispatch_table") else 1
        score_validation = 8 if (heuristics.get("per_character_validation") or heuristics.get("validators")) else 2
        
        avg_score = (score_binary + score_string + score_import + score_runtime + score_hooking + score_validation) / 6
        overall = "High" if avg_score >= 5.5 else ("Medium" if avg_score >= 3.0 else "Low")
        
        self._row("Binary Surface", str(score_binary))
        self._row("String Surface", str(score_string))
        self._row("Import Surface", str(score_import))
        self._row("Runtime Surface", str(score_runtime))
        self._row("Hooking Surface", str(score_hooking))
        self._row("Validation Surface", str(score_validation))
        
        oc = C.R if overall == "High" else (C.O if overall == "Medium" else C.G)
        self._row("Overall Interest", overall, value_colour=oc)

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
