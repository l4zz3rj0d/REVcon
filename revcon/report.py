import json
import sys
from typing import Dict, Any, List
from colorama import Fore, Back, Style

class ReportGenerator:
    """Formats and prints binary reconnaissance findings to the terminal or exports to JSON."""

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    def render_json(self) -> None:
        """Prints the entire metadata structure as raw JSON."""
        print(json.dumps(self.metadata, indent=4))

    def render_terminal(self) -> None:
        """Renders a premium CLI report resembling professional tools like capa and PEStudio."""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f" {Fore.WHITE}{Style.BRIGHT}REVcon Reconnaissance & Triage Report{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")

        # 1. Target Information
        intel = self.metadata.get("binary_intel", {})
        lang = self.metadata.get("language", {})
        predicted = self.metadata.get("predicted_challenge", {})
        
        print(f"{Fore.CYAN}{Style.BRIGHT}--- TARGET METADATA ---{Style.RESET_ALL}")
        print(f" {Style.BRIGHT}File Size:{Style.RESET_ALL}    {intel.get('file_size', 0)} bytes")
        print(f" {Style.BRIGHT}Format:{Style.RESET_ALL}       {Fore.GREEN}{intel.get('format', 'Unknown')}{Style.RESET_ALL}")
        print(f" {Style.BRIGHT}Architecture: {Style.RESET_ALL}{intel.get('arch', 'Unknown')} ({intel.get('bitness', 'Unknown')})")
        print(f" {Style.BRIGHT}Endianness:{Style.RESET_ALL}   {intel.get('endianness', 'Unknown')}")
        print(f" {Style.BRIGHT}Compiler:{Style.RESET_ALL}     {intel.get('compiler', 'Unknown')}")
        print(f" {Style.BRIGHT}Build Info:{Style.RESET_ALL}   {intel.get('build_info', 'Unknown')}")
        print(f" {Style.BRIGHT}Language:{Style.RESET_ALL}     {Fore.YELLOW}{lang.get('language', 'Unknown')}{Style.RESET_ALL} (Confidence: {lang.get('confidence', 0)}%)")
        print(f" {Style.BRIGHT}Challenge Type:{Style.RESET_ALL} {Fore.MAGENTA}{predicted.get('type', 'Unknown')}{Style.RESET_ALL} (Confidence: {predicted.get('confidence', 0)}%)\n")

        # 2. Security Mitigations
        print(f"{Fore.CYAN}{Style.BRIGHT}--- SECURITY MITIGATIONS ---{Style.RESET_ALL}")
        sec = self.metadata.get("security", {})
        for mitigation, details in sec.items():
            status = details.get("status", "Unknown")
            enabled = details.get("enabled", False)
            explanation = details.get("explanation", "")
            
            color = Fore.GREEN if enabled else Fore.RED
            # Fix checksec specific output status colors
            if "enabled" in status.lower() or "found" in status.lower() or "full" in status.lower():
                color = Fore.GREEN
            elif "disabled" in status.lower() or "no " in status.lower():
                color = Fore.RED
            elif "partial" in status.lower():
                color = Fore.YELLOW

            print(f" {Style.BRIGHT}{mitigation:<8}:{Style.RESET_ALL} {color}{status:<30}{Style.RESET_ALL}")
            print(f"   {Fore.LIGHTBLACK_EX}└─ {explanation}{Style.RESET_ALL}")
        print()

        # 3. Heuristics & Reversing Clues
        heuristics = self.metadata.get("heuristics", {})
        print(f"{Fore.CYAN}{Style.BRIGHT}--- REVERSE ENGINEERING HEURISTICS ---{Style.RESET_ALL}")
        
        # Expected Length
        length = heuristics.get("expected_input_length")
        len_str = f"{Fore.GREEN}{length}{Style.RESET_ALL}" if length else f"{Fore.YELLOW}None detected{Style.RESET_ALL}"
        print(f" {Style.BRIGHT}Expected Input Length:{Style.RESET_ALL} {len_str}")
        
        # Character Validation
        char_val = heuristics.get("per_character_validation", False)
        char_str = f"{Fore.GREEN}Yes (Character-by-character loops detected){Style.RESET_ALL}" if char_val else "No"
        print(f" {Style.BRIGHT}Per-Char Validation:{Style.RESET_ALL}   {char_str}")
        
        # Function dispatch
        dispatch = heuristics.get("function_dispatch_table", False)
        dispatch_str = f"{Fore.YELLOW}Yes (Dispatch tables / Dynamic jumps found){Style.RESET_ALL}" if dispatch else "No"
        print(f" {Style.BRIGHT}Function Dispatch:{Style.RESET_ALL}     {dispatch_str}")

        # XOR loops
        xor = heuristics.get("xor_loops_detected", False)
        xor_str = f"{Fore.RED}Yes (XOR decryption/obfuscation loops found){Style.RESET_ALL}" if xor else "No"
        print(f" {Style.BRIGHT}XOR Loops Detected:{Style.RESET_ALL}    {xor_str}")

        # Base64
        b64 = heuristics.get("base64_detected", False)
        b64_str = f"{Fore.GREEN}Yes (Base64 character map present in strings){Style.RESET_ALL}" if b64 else "No"
        print(f" {Style.BRIGHT}Base64 Routine:{Style.RESET_ALL}        {b64_str}")

        # Crypto
        crypto = heuristics.get("crypto_signatures", [])
        crypto_str = f"{Fore.YELLOW}{', '.join(crypto)}{Style.RESET_ALL}" if crypto else "None"
        print(f" {Style.BRIGHT}Crypto Algorithms:{Style.RESET_ALL}     {crypto_str}")

        # Packed
        packed = heuristics.get("packed_binary", False)
        packed_str = f"{Fore.RED}Yes (Packed binary indicators / UPX found){Style.RESET_ALL}" if packed else "No"
        print(f" {Style.BRIGHT}Packed Binary:{Style.RESET_ALL}         {packed_str}\n")

        # 4. Section Entropy (only print sections of interest or high entropy)
        entropy = self.metadata.get("entropy", {})
        sections = entropy.get("sections", [])
        if sections:
            print(f"{Fore.CYAN}{Style.BRIGHT}--- SECTION ENTROPY ANALYSIS ---{Style.RESET_ALL}")
            print(f"  {'Section':<15} {'Size (Bytes)':<15} {'Entropy':<10} {'Status':<30}")
            print(f"  {'-'*15} {'-'*15} {'-'*10} {'-'*30}")
            for sec_data in sections:
                ent = sec_data.get("entropy", 0.0)
                status = sec_data.get("status", "")
                name = sec_data.get("name", "Unknown")
                size = sec_data.get("size", 0)
                
                color = Fore.RESET
                if ent > 7.2:
                    color = Fore.RED + Style.BRIGHT
                elif ent > 6.0:
                    color = Fore.YELLOW
                
                print(f"  {color}{name:<15} {size:<15} {ent:<10} {status}{Style.RESET_ALL}")
            print()

        # 5. Imports & External APIs
        imports = self.metadata.get("imports", {})
        flagged_imports = imports.get("flagged_imports", {})
        if flagged_imports:
            print(f"{Fore.CYAN}{Style.BRIGHT}--- HIGH RELEVANCE IMPORTS ---{Style.RESET_ALL}")
            for imp_name, desc in flagged_imports.items():
                print(f"  {Fore.YELLOW}{imp_name:<12}{Style.RESET_ALL} → {desc}")
            print()

        # 6. Symbols & High Value Targets
        symbols = self.metadata.get("symbols", {})
        hvt = symbols.get("high_value_targets", [])
        if hvt:
            print(f"{Fore.CYAN}{Style.BRIGHT}--- HIGH VALUE TARGET SYMBOLS ---{Style.RESET_ALL}")
            for i, target in enumerate(hvt, 1):
                print(f"  {i}. {Fore.GREEN}{target}{Style.RESET_ALL}")
            print()

        # 7. Categorized Strings
        strings = self.metadata.get("strings", {})
        categories = strings.get("categories", {})
        has_strings_of_interest = any(len(lst) > 0 for lst in categories.values())
        
        if has_strings_of_interest:
            print(f"{Fore.CYAN}{Style.BRIGHT}--- INTERESTING STRINGS BY CATEGORY ---{Style.RESET_ALL}")
            for cat_name, lst in categories.items():
                if lst:
                    title = cat_name.replace("_", " ").upper()
                    print(f"  {Style.BRIGHT}[{title}]{Style.RESET_ALL}")
                    # Print top 5 strings in each category to avoid overwhelming the screen
                    for s in lst[:5]:
                        # Shorten extremely long strings
                        short = s if len(s) < 80 else s[:77] + "..."
                        print(f"    • {short}")
                    if len(lst) > 5:
                        print(f"    {Fore.LIGHTBLACK_EX}... ({len(lst) - 5} more strings hidden. Use --verbose to see all){Style.RESET_ALL}")
            print()

        # 8. Plugin Findings
        plugin_findings = self.metadata.get("plugin_findings", {})
        has_plugin_detections = any(res.get("detected", False) for res in plugin_findings.values())
        if has_plugin_detections:
            print(f"{Fore.CYAN}{Style.BRIGHT}--- DYNAMIC PLUGIN DETECTIONS ---{Style.RESET_ALL}")
            for p_name, res in plugin_findings.items():
                if res.get("detected", False):
                    print(f"  {Style.BRIGHT}[{p_name}]{Style.RESET_ALL}")
                    for finding in res.get("findings", []):
                        print(f"    - {finding}")
            print()

        # 8b. Flag Intelligence
        flag_intel = self.metadata.get("flag_intel")
        if flag_intel:
            print(f"{Fore.CYAN}{Style.BRIGHT}--- FLAG INTELLIGENCE ---{Style.RESET_ALL}")
            print(f"  {Style.BRIGHT}Target Format:{Style.RESET_ALL}    {flag_intel.get('flag_format', 'N/A')}")
            print(f"  {Style.BRIGHT}Search Regex:{Style.RESET_ALL}     {flag_intel.get('regex', 'N/A')}")

            confidence = flag_intel.get("confidence", "LOW")
            conf_color = Fore.GREEN if confidence == "HIGH" else Fore.YELLOW if confidence == "MEDIUM" else Fore.RED
            print(f"  {Style.BRIGHT}Confidence:{Style.RESET_ALL}       {conf_color}{confidence}{Style.RESET_ALL}")

            matches = flag_intel.get("matches", [])
            if matches:
                print(f"\n  {Style.BRIGHT}Direct Matches:{Style.RESET_ALL}")
                for m in matches:
                    print(f"    {Fore.GREEN}{m}{Style.RESET_ALL}")
            else:
                print(f"\n  {Style.BRIGHT}Direct Matches:{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}None{Style.RESET_ALL}")

            partials = flag_intel.get("partial_matches", [])
            if partials:
                print(f"  {Style.BRIGHT}Partial Matches:{Style.RESET_ALL}")
                for p in partials[:10]:
                    short = p if len(p) < 80 else p[:77] + "..."
                    print(f"    {Fore.YELLOW}{short}{Style.RESET_ALL}")
                if len(partials) > 10:
                    print(f"    {Fore.LIGHTBLACK_EX}... ({len(partials) - 10} more hidden){Style.RESET_ALL}")
            else:
                print(f"  {Style.BRIGHT}Partial Matches:{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}None{Style.RESET_ALL}")
            print()


        # 9. Recommendations / Analyst Summary
        guidance = self.metadata.get("analyst_guidance", {})
        print(f"{Fore.YELLOW}{Style.BRIGHT}{'='*60}")
        print(f" ANALYST SUMMARY & RECOMMENDATIONS")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f" {Style.BRIGHT}Language / Runtime:{Style.RESET_ALL} {lang.get('language', 'Unknown')}")
        print(f" {Style.BRIGHT}Predicted Challenge:{Style.RESET_ALL} {predicted.get('type', 'Unknown')}")
        if length:
            print(f" {Style.BRIGHT}Expected Input Length:{Style.RESET_ALL} {length} characters")
        
        # High value targets
        if hvt:
            print(f" {Style.BRIGHT}Primary Functions:{Style.RESET_ALL}   {', '.join(hvt[:3])}")
            
        print(f"\n {Style.BRIGHT}{Fore.CYAN}Analysis Strategies:{Style.RESET_ALL}")
        for strategy in guidance.get("strategies", []):
            print(f"  • {strategy}")
        if not guidance.get("strategies"):
            print("  • No special strategies determined for this compiler layout.")
            
        print(f"\n {Style.BRIGHT}{Fore.GREEN}Recommended Next Step:{Style.RESET_ALL}")
        print(f"  {Style.BRIGHT}{guidance.get('next_steps')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
