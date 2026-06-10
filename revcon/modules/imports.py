from typing import List, Dict, Any
from elftools.elf.elffile import ELFFile
import pefile

class ImportIntelligence:
    """Extracts imported library functions and highlights reverse engineering/CTF relevance."""

    def __init__(self, filepath: str, binary_format: str):
        self.filepath = filepath
        self.format = binary_format
        self.target_imports = {
            "strcmp": "String comparison (frequent password/flag validator)",
            "strncmp": "Bounded string comparison (length-checked flag validator)",
            "memcmp": "Binary memory comparison (likely checking key or flag bytes)",
            "scanf": "Formatted user input collector (potential format string or overflow target)",
            "gets": "CRITICAL: Insecure user input collector (unbounded stack buffer overflow target)",
            "fgets": "Safe user input collector (bounded stack buffer reading)",
            "read": "Low-level system read (input/payload reading)",
            "write": "Low-level system write (outputting messages/errors)",
            "printf": "Formatted printer (potential Format String Vulnerability)",
            "puts": "Standard string output printer",
            "rand": "PRNG random generator (predictable seeds, check srand calls)",
            "srand": "PRNG seed initialization (often seeded with time(NULL) in crackmes)",
            "time": "System time fetcher (commonly used to seed random checks)"
        }

    def analyze(self) -> Dict[str, Any]:
        """Analyzes binary imports and flags targets."""
        all_imports = []

        if self.format == "ELF":
            all_imports = self._extract_elf_imports()
        elif self.format == "PE":
            all_imports = self._extract_pe_imports()
        elif self.format == "Mach-O":
            all_imports = self._extract_macho_imports()

        # Match target imports and build findings
        flagged = {}
        for imp in all_imports:
            # Match case-insensitively and remove dynamic link decorators (e.g. strcmp@GLIBC)
            base_imp = imp.split("@")[0].strip("_").lower()
            for target, description in self.target_imports.items():
                if base_imp == target:
                    flagged[target] = description

        return {
            "all_imports": all_imports,
            "flagged_imports": flagged
        }

    def _extract_elf_imports(self) -> List[str]:
        """Extracts imports from ELF file dynsym table."""
        imports = set()
        try:
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym:
                    for sym in dynsym.iter_symbols():
                        # UNDEF symbols are imported from external shared objects
                        if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
                            imports.add(sym.name)
        except Exception:
            pass
        return sorted(list(imports))

    def _extract_pe_imports(self) -> List[str]:
        """Extracts imports from PE Import Address Table."""
        imports = set()
        try:
            pe = pefile.PE(self.filepath)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.add(imp.name.decode("utf-8", errors="ignore"))
            pe.close()
        except Exception:
            pass
        return sorted(list(imports))

    def _extract_macho_imports(self) -> List[str]:
        """Extracts imports from Mach-O dyld command indicators."""
        # macho dynamic imports will fall back if not parsed easily
        return []
