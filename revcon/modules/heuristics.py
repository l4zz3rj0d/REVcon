import re
from typing import Dict, Any, List, Set, Optional
from elftools.elf.elffile import ELFFile
import pefile
from capstone import *
from revcon.utils import log_verbose

class ReverseEngineeringHeuristics:
    """Uses Capstone disassembly to scan for reverse engineering heuristics like validation, loops, dynamic dispatch, XOR, and crypto."""

    def __init__(self, filepath: str, arch: str, bitness: str, format: str, strings: List[str], verbose: bool = False):
        self.filepath = filepath
        self.arch = arch
        self.bitness = bitness
        self.format = format
        self.strings = strings
        self.verbose = verbose

    def analyze(self) -> Dict[str, Any]:
        """Disassembles executable segments and runs heuristics checks."""
        result = {
            "expected_input_length": None,
            "per_character_validation": False,
            "function_dispatch_table": False,
            "xor_loops_detected": False,
            "base64_detected": False,
            "crypto_signatures": [],
            "packed_binary": False,
            "validators": []
        }

        # 1. Base64 Detection (check strings)
        b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        b64_url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for s in self.strings:
            if b64_alphabet in s or b64_url_alphabet in s:
                result["base64_detected"] = True
                break

        # 2. Packed Binary Check (check strings & sections)
        for s in self.strings:
            if "UPX!" in s or "UPX0" in s or "UPX1" in s:
                result["packed_binary"] = True
                break

        # 3. Crypto Signatures (check strings)
        crypto_keywords = {
            "AES": ["aes", "rijndael", "aes_key", "aes_encrypt"],
            "RC4": ["rc4", "arcfour", "rc4_init", "rc4_crypt"],
            "ChaCha20": ["chacha20", "chacha20_block"],
            "SHA1": ["sha1", "sha-1", "sha1_init"],
            "SHA256": ["sha256", "sha-256", "sha256_init"],
            "MD5": ["md5", "md5_init", "md5_crypt"]
        }
        for s in self.strings:
            s_l = s.lower()
            for cipher, kws in crypto_keywords.items():
                if any(kw in s_l for kw in kws) and cipher not in result["crypto_signatures"]:
                    result["crypto_signatures"].append(cipher)

        # 4. Disassembly Heuristics
        code_bytes, base_addr = self._extract_code_segment()
        if not code_bytes:
            log_verbose("No executable code segment extracted. Skipping disassembly heuristics.", self.verbose)
            return result

        cs = self._init_capstone()
        if not cs:
            log_verbose("Failed to initialize Capstone disassembler. Skipping disassembly heuristics.", self.verbose)
            return result

        try:
            instructions = list(cs.disasm(code_bytes, base_addr))
            log_verbose(f"Disassembled {len(instructions)} instructions.", self.verbose)
            
            # Run heuristic scanners on instructions
            self._scan_length_checks(instructions, result)
            self._scan_per_char_validation(instructions, result)
            self._scan_validators(instructions, result)
            self._scan_function_dispatch(instructions, result)
            self._scan_xor_loops(instructions, result)
            self._scan_crypto_constants(code_bytes, result)

        except Exception as e:
            log_verbose(f"Error during Capstone analysis: {str(e)}", self.verbose)

        return result

    def _extract_code_segment(self) -> tuple[Optional[bytes], int]:
        """Extracts executable section bytes and base virtual address."""
        try:
            if self.format == "ELF":
                with open(self.filepath, "rb") as f:
                    elf = ELFFile(f)
                    # Get .text section
                    text_sec = elf.get_section_by_name(".text")
                    if text_sec:
                        return text_sec.data(), text_sec['sh_addr']
                    
                    # Fallback: find first executable segment
                    for seg in elf.iter_segments():
                        if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 1): # Executable
                            return seg.data(), seg['p_vaddr']
            elif self.format == "PE":
                pe = pefile.PE(self.filepath)
                # Find .text section
                for sec in pe.sections:
                    name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
                    if ".text" in name or (sec.Characteristics & 0x20000000): # IMAGE_SCN_MEM_EXECUTE
                        data = sec.get_data()
                        base_addr = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
                        pe.close()
                        return data, base_addr
                pe.close()
        except Exception:
            pass
        return None, 0

    def _init_capstone(self) -> Optional[Cs]:
        """Initializes Capstone with the correct architecture and mode."""
        arch_map = {
            "x64": (CS_ARCH_X86, CS_MODE_64),
            "x86": (CS_ARCH_X86, CS_MODE_32),
            "ARM64": (CS_ARCH_ARM64, CS_MODE_ARM),
            "ARM": (CS_ARCH_ARM, CS_MODE_ARM),
            "MIPS": (CS_ARCH_MIPS, CS_MODE_MIPS32)
        }

        if self.arch not in arch_map:
            return None

        cs_arch, cs_mode = arch_map[self.arch]
        try:
            return Cs(cs_arch, cs_mode)
        except Exception:
            return None

    def _scan_length_checks(self, instructions: List[Any], result: Dict[str, Any]) -> None:
        """Looks for input length comparisons, e.g. cmp rsi, 0x1f."""
        # Registers frequently holding string/buffer sizes
        length_regs = {"eax", "rax", "ebx", "rbx", "ecx", "rcx", "edx", "rdx", "esi", "rsi", "edi", "rdi"}
        length_candidates = {}

        for insn in instructions:
            if insn.mnemonic == "cmp":
                # Matches: cmp reg, imm (e.g. cmp rsi, 0x20)
                parts = [p.strip() for p in insn.op_str.split(",")]
                if len(parts) == 2:
                    reg, val = parts[0], parts[1]
                    if reg in length_regs:
                        try:
                            # Parse hex or decimal integer
                            int_val = int(val, 16) if val.startswith("0x") else int(val)
                            # String sizes in CTFs are typically between 4 and 100
                            if 4 <= int_val <= 100:
                                length_candidates[int_val] = length_candidates.get(int_val, 0) + 1
                        except ValueError:
                            pass

        if length_candidates:
            # Get the most common length check constant
            best_len = max(length_candidates, key=length_candidates.get)
            # If it appeared at least once
            result["expected_input_length"] = best_len

    def _scan_per_char_validation(self, instructions: List[Any], result: Dict[str, Any]) -> None:
        """Detects if per-character validation loops exist (e.g. cmp al, 0x41)."""
        # Low byte registers frequently used for character checks
        byte_regs = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "spl", "bpl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
        byte_cmp_count = 0

        for insn in instructions:
            if insn.mnemonic == "cmp":
                parts = [p.strip() for p in insn.op_str.split(",")]
                if len(parts) == 2:
                    reg, val = parts[0], parts[1]
                    if reg in byte_regs:
                        # Character codes typically fit in ASCII range 32 to 126
                        try:
                            int_val = int(val, 16) if val.startswith("0x") else int(val)
                            if 0 <= int_val <= 255:
                                byte_cmp_count += 1
                        except ValueError:
                            pass

        # If we see multiple byte comparisons, it indicates character checks
        if byte_cmp_count >= 5:
            result["per_character_validation"] = True

    def _scan_validators(self, instructions: List[Any], result: Dict[str, Any]) -> None:
        """Detects custom comparison loops, like input[i] ^ constant[i] == x"""
        byte_regs = {"al", "bl", "cl", "dl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
        
        validators = set()
        for idx, insn in enumerate(instructions):
            if insn.mnemonic in ("xor", "add", "sub"):
                parts = [p.strip() for p in insn.op_str.split(",")]
                if len(parts) == 2 and parts[0] in byte_regs:
                    # Look ahead a few instructions for a cmp
                    for look_ahead in range(1, 5):
                        if idx + look_ahead < len(instructions):
                            next_insn = instructions[idx + look_ahead]
                            if next_insn.mnemonic == "cmp":
                                cmp_parts = [p.strip() for p in next_insn.op_str.split(",")]
                                if len(cmp_parts) == 2 and cmp_parts[0] == parts[0]:
                                    validators.add(insn.mnemonic.upper())
                                    break
        
        for v in validators:
            result["validators"].append(f"{v} loop")

    def _scan_function_dispatch(self, instructions: List[Any], result: Dict[str, Any]) -> None:
        """Looks for calls/jumps via function tables (e.g. call qword ptr [rax + rcx*8])."""
        dispatch_patterns = [
            r'qword ptr \[',
            r'dword ptr \[',
            r'\[r[a-z0-9]+\s*\+\s*r[a-z0-9]+'
        ]

        for insn in instructions:
            if insn.mnemonic in ("call", "jmp"):
                if any(re.search(pat, insn.op_str) for pat in dispatch_patterns):
                    result["function_dispatch_table"] = True
                    break

    def _scan_xor_loops(self, instructions: List[Any], result: Dict[str, Any]) -> None:
        """Detects backward loops that contain a XOR operation (typical of XOR decryption/encoding loops)."""
        # Map instructions by address for quick lookup
        addr_map = {insn.address: i for i, insn in enumerate(instructions)}
        
        for idx, insn in enumerate(instructions):
            # Check for conditional jump instructions (backward)
            if insn.mnemonic.startswith("j") and not insn.mnemonic == "jmp":
                try:
                    target_addr = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                    if target_addr in addr_map:
                        target_idx = addr_map[target_addr]
                        # Check if jump is backward (looping back)
                        if target_idx < idx:
                            # Scan instructions inside the loop body for XOR
                            loop_instructions = instructions[target_idx:idx]
                            for loop_insn in loop_instructions:
                                if loop_insn.mnemonic == "xor":
                                    parts = [p.strip() for p in loop_insn.op_str.split(",")]
                                    if len(parts) == 2:
                                        # Exclude 'xor eax, eax' or similar which clears registers
                                        if parts[0] != parts[1]:
                                            result["xor_loops_detected"] = True
                                            return
                except ValueError:
                    pass

    def _scan_crypto_constants(self, code_bytes: bytes, result: Dict[str, Any]) -> None:
        """Scans code/data bytes for typical cryptographic algorithm constants."""
        # MD5 initialization constants
        md5_constants = [b"\x01\x23\x45\x67", b"\x89\xab\xcd\xef", b"\xfe\xdc\xba\x98", b"\x76\x54\x32\x10"]
        # SHA256 initialization constants (H0-H7)
        sha256_constants = [
            b"\x6a\x09\xe6\x67", b"\xbb\x67\xae\x85", b"\x3c\x6e\xf3\x72", b"\xa5\x4f\xf5\x3a",
            b"\x51\x0e\x52\x7f", b"\x9b\x05\x68\x8c", b"\x1f\x83\xd9\xab", b"\x5b\xe0\xcd\x19"
        ]

        # Check MD5
        md5_matches = sum(1 for c in md5_constants if c in code_bytes)
        if md5_matches >= 3 and "MD5" not in result["crypto_signatures"]:
            result["crypto_signatures"].append("MD5")

        # Check SHA256
        sha_matches = sum(1 for c in sha256_constants if c in code_bytes)
        if sha_matches >= 4 and "SHA256" not in result["crypto_signatures"]:
            result["crypto_signatures"].append("SHA256")
