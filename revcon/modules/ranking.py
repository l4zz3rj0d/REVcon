import struct
from typing import Dict, Any, List
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from elftools.elf.elffile import ELFFile

class FunctionRanker:
    """Scores functions based on suspicious characteristics (crypto, validation, execution)."""

    def __init__(self, filepath: str, arch: str, bitness: str, format: str):
        self.filepath = filepath
        self.arch = arch
        self.bitness = bitness
        self.format = format
        self.functions = []

    def analyze(self, code_bytes: bytes, base_addr: int, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts functions and ranks them based on heuristics and runtime intelligence."""
        if self.format == "ELF":
            self._extract_elf_functions()
            
        # If stripped or non-ELF, we might not have functions, fallback to generic approach later if needed.
        if not self.functions:
            return []

        cs_mode = CS_MODE_64 if self.bitness == "64" else CS_MODE_32
        try:
            cs = Cs(CS_ARCH_X86, cs_mode)
        except Exception:
            return []

        ranked_funcs = []
        for func in self.functions:
            score = 0
            reasons = []
            
            # Static scoring based on function content
            start_offset = func["addr"] - base_addr
            if start_offset < 0 or start_offset >= len(code_bytes):
                continue
                
            end_offset = min(start_offset + func["size"], len(code_bytes))
            func_bytes = code_bytes[start_offset:end_offset]
            
            try:
                instructions = list(cs.disasm(func_bytes, func["addr"]))
            except Exception:
                continue
                
            # Heuristics
            xor_count = 0
            cmp_count = 0
            for insn in instructions:
                if insn.mnemonic == "xor":
                    xor_count += 1
                elif insn.mnemonic in ("cmp", "test"):
                    cmp_count += 1
            
            if xor_count > 3:
                score += 30
                reasons.append("decryption logic / XOR loops")
                
            if cmp_count > 5:
                score += 20
                reasons.append("validation logic")
                
            # Name-based scoring (from existing symbols logic)
            name_lower = func["name"].lower()
            if any(kw in name_lower for kw in ["crypto", "decrypt", "encrypt", "aes", "hash"]):
                score += 40
                reasons.append("crypto usage")
            elif any(kw in name_lower for kw in ["validate", "check", "verify", "password"]):
                score += 30
                reasons.append("validation routine")

            if score > 0:
                ranked_funcs.append({
                    "name": func["name"],
                    "addr": hex(func["addr"]),
                    "size": func["size"],
                    "score": score,
                    "reasons": reasons
                })
                
        # Sort by score
        ranked_funcs.sort(key=lambda x: x["score"], reverse=True)
        return ranked_funcs

    def _extract_elf_functions(self):
        """Extracts function boundaries from ELF symbol tables."""
        try:
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                for section_name in [".symtab", ".dynsym"]:
                    sec = elf.get_section_by_name(section_name)
                    if sec:
                        for sym in sec.iter_symbols():
                            if sym.name and sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                                self.functions.append({
                                    "name": sym.name,
                                    "addr": sym['st_value'],
                                    "size": sym['st_size']
                                })
        except Exception:
            pass
