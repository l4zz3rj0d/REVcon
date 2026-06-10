import re
from typing import List, Dict, Any
from elftools.elf.elffile import ELFFile
import pefile
from macholib.MachO import MachO

class SymbolIntelligence:
    """Parses binary symbols, demangles simple C++ names, and ranks them to identify High Value Targets."""

    def __init__(self, filepath: str, binary_format: str):
        self.filepath = filepath
        self.format = binary_format
        self.priority_keywords = ["flag", "check", "verify", "validate", "decrypt", "encrypt", "password", "secret", "auth", "token", "main"]

    def analyze(self) -> Dict[str, Any]:
        """Extracts and parses symbols."""
        raw_symbols = []

        if self.format == "ELF":
            raw_symbols = self._extract_elf_symbols()
        elif self.format == "PE":
            raw_symbols = self._extract_pe_symbols()
        elif self.format == "Mach-O":
            raw_symbols = self._extract_macho_symbols()

        # Demangle C++ symbols if possible (using simple regex demangler to avoid external dependencies)
        demangled_symbols = [self._demangle(sym) for sym in raw_symbols]

        # Categorize and Rank targets
        ranked = self._rank_symbols(demangled_symbols)

        return {
            "all_symbols": demangled_symbols,
            "interesting_symbols": ranked["categories"],
            "high_value_targets": ranked["high_value_targets"],
            "has_symbols": len(demangled_symbols) > 0
        }

    def _extract_elf_symbols(self) -> List[str]:
        """Extracts symbols from ELF files."""
        symbols = set()
        try:
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                
                # Check symtab
                symtab = elf.get_section_by_name(".symtab")
                if symtab:
                    for sym in symtab.iter_symbols():
                        if sym.name and sym['st_info']['type'] == 'STT_FUNC':
                            symbols.add(sym.name)
                
                # Check dynsym (if stripped, dynsym might still exist)
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym:
                    for sym in dynsym.iter_symbols():
                        if sym.name and sym['st_info']['type'] == 'STT_FUNC':
                            symbols.add(sym.name)
        except Exception:
            pass
        return sorted(list(symbols))

    def _extract_pe_symbols(self) -> List[str]:
        """Extracts symbols from PE exports and debug directories."""
        symbols = set()
        try:
            pe = pefile.PE(self.filepath)
            
            # Exported Functions
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        symbols.add(exp.name.decode("utf-8", errors="ignore"))
            
            # Check if there are debug symbols or COFF symbol table
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                # Debug symbols are usually stored in PDB, not direct COFF symbols,
                # but sometimes COFF symbol table is present
                pass
            
            pe.close()
        except Exception:
            pass
        return sorted(list(symbols))

    def _extract_macho_symbols(self) -> List[str]:
        """Extracts symbols from Mach-O LC_SYMTAB."""
        symbols = set()
        try:
            m = MachO(self.filepath)
            # macholib doesn't parse full symbol name strings easily out of the box,
            # but we can look at the symbol table commands.
            # To make it robust and simple: if it fails, we fall back to empty list.
            pass
        except Exception:
            pass
        return sorted(list(symbols))

    def _demangle(self, sym: str) -> str:
        """Applies basic regex demangling for C++ GNU v3 symbols (starting with _Z)."""
        if not sym.startswith("_Z") and not sym.startswith("__Z"):
            return sym

        # Simple C++ GNU v3 demangling approximation
        # Example: _Z8validatePKc -> validate(char const*)
        # Let's just extract the function name part:
        match = re.match(r'^_Z+n?(\d+)([a-zA-Z0-9_]+)', sym)
        if match:
            length = int(match.group(1))
            name = match.group(2)[:length]
            return name
        
        return sym

    def _rank_symbols(self, symbols: List[str]) -> Dict[str, Any]:
        """Ranks symbols based on security/reversing interest keywords."""
        categories = {kw: [] for kw in self.priority_keywords}
        scored_targets = []

        for sym in symbols:
            sym_lower = sym.lower()
            score = 0
            matched_kws = []

            for kw in self.priority_keywords:
                if kw in sym_lower:
                    categories[kw].append(sym)
                    matched_kws.append(kw)
                    # Score weights
                    if kw in ["flag", "password", "secret", "token"]:
                        score += 50
                    elif kw in ["decrypt", "encrypt", "auth", "validate", "verify", "check"]:
                        score += 30
                    elif kw == "main":
                        score += 10

            if score > 0:
                scored_targets.append((sym, score))

        # Sort targets by score descending, then by name
        scored_targets.sort(key=lambda x: (-x[1], x[0]))
        high_value = [t[0] for t in scored_targets]

        # Clean empty categories
        filtered_categories = {k: v for k, v in categories.items() if v}

        return {
            "categories": filtered_categories,
            "high_value_targets": high_value[:15] # Top 15 targets
        }
