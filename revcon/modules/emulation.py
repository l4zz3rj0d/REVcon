import struct
from typing import Dict, Any, List
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import re

class EmulationEngine:
    """Emulates or statically reconstructs constants and stack strings."""

    def __init__(self, filepath: str, arch: str, bitness: str, code_bytes: bytes, base_addr: int):
        self.filepath = filepath
        self.arch = arch
        self.bitness = bitness
        self.code_bytes = code_bytes
        self.base_addr = base_addr

    def analyze(self) -> Dict[str, Any]:
        """Runs the reconstruction engine to find stack strings and overlapping writes."""
        findings = []
        if self.arch != "x64" and self.arch != "x86":
            return {"reconstructed_buffers": []}

        cs_mode = CS_MODE_64 if self.bitness == "64" else CS_MODE_32
        try:
            cs = Cs(CS_ARCH_X86, cs_mode)
            instructions = list(cs.disasm(self.code_bytes, self.base_addr))
        except Exception:
            return {"reconstructed_buffers": []}

        # Track consecutive stack writes
        stack_writes = []
        
        for insn in instructions:
            if insn.mnemonic == "mov":
                # Look for mov [rbp - XX], imm  or  mov [rsp + XX], imm
                # e.g., mov dword ptr [rbp - 0x10], 0x6c357b30
                if "ptr [" in insn.op_str and ("rbp" in insn.op_str or "rsp" in insn.op_str):
                    parts = insn.op_str.split(",")
                    if len(parts) == 2:
                        dst = parts[0].strip()
                        src = parts[1].strip()
                        
                        if src.startswith("0x"):
                            try:
                                imm = int(src, 16)
                                # Extract offset if exists
                                offset = 0
                                off_match = re.search(r'([+-]\s*0x[0-9a-fA-F]+)', dst)
                                if off_match:
                                    offset_str = off_match.group(1).replace(" ", "")
                                    offset = int(offset_str, 16)
                                    
                                stack_writes.append({"addr": insn.address, "offset": offset, "val": imm})
                            except ValueError:
                                pass
            else:
                # If we hit a call or non-mov, evaluate current stack_writes chain
                if len(stack_writes) >= 3:
                    reconstructed = self._reconstruct(stack_writes)
                    if reconstructed and len(reconstructed) > 4:
                        findings.append({
                            "type": "Stack String",
                            "ascii": reconstructed,
                            "start_addr": hex(stack_writes[0]["addr"])
                        })
                stack_writes = []

        return {"reconstructed_buffers": findings}

    def _reconstruct(self, writes: List[Dict[str, Any]]) -> str:
        """Attempts to reconstruct an ASCII string from a series of writes."""
        # Sort by offset to assemble memory
        sorted_writes = sorted(writes, key=lambda x: x["offset"])
        
        raw_bytes = bytearray()
        for w in sorted_writes:
            val = w["val"]
            try:
                # Try to pack it as a 32-bit or 64-bit integer
                if val <= 0xFFFFFFFF:
                    raw_bytes.extend(struct.pack("<I", val))
                else:
                    raw_bytes.extend(struct.pack("<Q", val))
            except Exception:
                pass
                
        # Filter for printable ascii
        ascii_str = ""
        for b in raw_bytes:
            if 32 <= b <= 126:
                ascii_str += chr(b)
            elif b == 0:
                break # Null terminator
            else:
                pass # Ignore non-ascii for now
                
        return ascii_str
