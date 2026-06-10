import struct
import re
from typing import Dict, Any, List
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

class EmulationEngine:
    """Emulates or statically reconstructs constants, stack strings, and decoded obfuscated buffers."""

    def __init__(self, filepath: str, arch: str, bitness: str, code_bytes: bytes, base_addr: int):
        self.filepath = filepath
        self.arch = arch
        self.bitness = bitness
        self.code_bytes = code_bytes
        self.base_addr = base_addr
        
        # Read the entire file bytes for data sections scan
        self.file_bytes = b""
        try:
            with open(self.filepath, "rb") as f:
                self.file_bytes = f.read()
        except Exception:
            pass

    def analyze(self) -> Dict[str, Any]:
        """Runs the reconstruction engine to find stack strings and encoded constants."""
        findings = []

        # 1. Stack Strings Recovery
        if self.arch == "x64" or self.arch == "x86":
            cs_mode = CS_MODE_64 if "64" in str(self.bitness) else CS_MODE_32
            try:
                cs = Cs(CS_ARCH_X86, cs_mode)
                instructions = list(cs.disasm(self.code_bytes, self.base_addr))
            except Exception:
                instructions = []
            
            # Track consecutive stack writes
            stack_writes = []
            for insn in instructions:
                if "ptr [" in insn.op_str and ("rbp" in insn.op_str or "rsp" in insn.op_str or "esp" in insn.op_str or "ebp" in insn.op_str):
                    parts = insn.op_str.split(",")
                    if len(parts) == 2:
                        dst = parts[0].strip()
                        src = parts[1].strip()
                        
                        if src.startswith("0x") or src.isdigit():
                            try:
                                imm = int(src, 16) if src.startswith("0x") else int(src)
                                size = 4
                                if "byte" in dst: size = 1
                                elif "word" in dst: size = 2
                                elif "dword" in dst: size = 4
                                elif "qword" in dst: size = 8
                                
                                offset = 0
                                off_match = re.search(r'([+-]\s*0x[0-9a-fA-F]+|[+-]\s*[0-9]+)', dst)
                                if off_match:
                                    offset_str = off_match.group(1).replace(" ", "")
                                    offset = int(offset_str, 16) if "0x" in offset_str else int(offset_str)
                                    
                                stack_writes.append({
                                    "addr": insn.address,
                                    "offset": offset,
                                    "val": imm,
                                    "size": size
                                })
                            except ValueError:
                                pass
                else:
                    if len(stack_writes) >= 3:
                        reconstructed = self._reconstruct_stack_string(stack_writes)
                        if reconstructed and len(reconstructed) >= 4:
                            findings.append({
                                "type": "Stack String",
                                "ascii": reconstructed,
                                "start_addr": hex(stack_writes[0]["addr"])
                            })
                    stack_writes = []

        # 2. Heuristic XOR/ADD/SUB Decryption Scanner
        decoded_buffers = self._scan_encoded_buffers()
        findings.extend(decoded_buffers)

        return {"reconstructed_buffers": findings}

    def _reconstruct_stack_string(self, writes: List[Dict[str, Any]]) -> str:
        """Attempts to reconstruct an ASCII string from a series of stack writes."""
        sorted_writes = sorted(writes, key=lambda x: x["offset"])
        
        raw_bytes = bytearray()
        for w in sorted_writes:
            val = w["val"]
            size = w["size"]
            try:
                if size == 1:
                    raw_bytes.append(val & 0xFF)
                elif size == 2:
                    raw_bytes.extend(struct.pack("<H", val & 0xFFFF))
                elif size == 4:
                    raw_bytes.extend(struct.pack("<I", val & 0xFFFFFFFF))
                elif size == 8:
                    raw_bytes.extend(struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))
            except Exception:
                pass
                
        ascii_str = ""
        for b in raw_bytes:
            if 32 <= b <= 126:
                ascii_str += chr(b)
            elif b == 0:
                break
        return ascii_str

    def _scan_encoded_buffers(self) -> List[Dict[str, Any]]:
        """Scans raw file data for simple single-byte XOR, ADD, and SUB encoded strings."""
        findings = []
        if not self.file_bytes or len(self.file_bytes) > 2 * 1024 * 1024:
            return findings

        # Scan section of the file
        scan_data = self.file_bytes[0x400:]
        
        methods = [
            ("XOR", lambda b, k: b ^ k),
            ("ADD", lambda b, k: (b + k) & 0xFF),
            ("SUB", lambda b, k: (b - k) & 0xFF)
        ]
                   
        seen = set()
        for method_name, trans_fn in methods:
            for key in range(1, 256):
                current_run = bytearray()
                for byte in scan_data:
                    dec = trans_fn(byte, key)
                    if 32 <= dec <= 126:
                        current_run.append(dec)
                    else:
                        if len(current_run) >= 8:
                            candidate = current_run.decode('utf-8', errors='ignore')
                            # Eliminate strings with consecutive identical characters (e.g. padding)
                            if not re.search(r'(.)\1\1\1', candidate):
                                most_common_char_count = max(candidate.count(c) for c in set(candidate))
                                if most_common_char_count / len(candidate) <= 0.4:
                                    # Ensure high percentage of alphanumeric / common flag chars
                                    alphanum_and_common = sum(1 for c in candidate if c.isalnum() or c in "_-{}[!]?@#%&*()")
                                    if (alphanum_and_common / len(candidate)) >= 0.85:
                                        if candidate not in seen:
                                            seen.add(candidate)
                                            findings.append({
                                                "type": f"{method_name}-decoded String",
                                                "ascii": candidate,
                                                "key": hex(key)
                                            })
                        current_run = bytearray()
                        
        return findings
