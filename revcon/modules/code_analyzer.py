import re
import struct
import os
from typing import Dict, Any, List, Set, Tuple, Optional
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection
import pefile

# Compiler boilerplate functions to hide from standard report output unless verbose is enabled.
BOILERPLATES = {
    "_start", "frame_dummy", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini",
    "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
    "__do_global_ctors_aux", "at_quick_exit", "atexit", "__security_init_cookie",
    "__scrt_common_main_seh", "_DllMainCRTStartup", "pre_c_init", "pre_cpp_init",
    "post_pogo_html", "guard_check_icall", "_guard_dispatch_icall_nop",
    "__cxa_finalize", "__gmon_start__"
}

class CodeAnalyzer:
    """Performs deep code analysis, call graph generation, function discovery, and environment variable recovery."""

    def __init__(self, filepath: str, arch: str, bitness: str, format: str, verbose: bool = False):
        self.filepath = filepath
        self.arch = arch
        self.bitness = bitness
        self.format = format
        self.verbose = verbose
        
        self.functions: Dict[int, Dict[str, Any]] = {}  # va -> info
        self.imports: Dict[int, str] = {}  # va -> name (PLT or IAT)
        self.exports: List[Dict[str, Any]] = []
        self.dependencies: List[str] = []
        self.recovered_envs: List[Dict[str, Any]] = []
        self.relationships: List[str] = []
        self.call_graph: Dict[str, List[str]] = {}
        
        self.relocs: Dict[int, str] = {}  # got_offset -> symbol_name
        self.plt_map: Dict[int, str] = {}  # plt_addr -> symbol_name
        
        self.sections_map = []
        self.file_bytes = b""
        
        self._load_file()

    def _load_file(self):
        try:
            with open(self.filepath, "rb") as f:
                self.file_bytes = f.read()
        except Exception:
            pass

    def analyze(self) -> Dict[str, Any]:
        """Runs the main code analysis pipeline."""
        if self.format == "ELF":
            self._analyze_elf()
        elif self.format == "PE":
            self._analyze_pe()

        # Disassemble each function, follow calls recursively to find new ones, and score them
        self._disassemble_and_analyze_functions()
        self._build_call_graph()

        # Clean up CsInsn objects to make them JSON serializable
        for func in self.functions.values():
            if "instructions" in func:
                del func["instructions"]

        # Keep only non-boilerplate functions for final reporting unless verbose is active
        reported_funcs = {}
        for va, func in self.functions.items():
            if func["name"] in BOILERPLATES and not self.verbose:
                continue
            reported_funcs[va] = func

        # Recalculate statistics
        functions_found = len(self.functions)
        analyzed_count = len(reported_funcs)
        interesting_count = sum(1 for f in reported_funcs.values() if f.get("score", 0) >= 30)

        return {
            "functions_found": functions_found,
            "analyzed_count": analyzed_count,
            "interesting_count": interesting_count,
            "dependencies": self.dependencies,
            "exports": [e for e in self.exports if self.verbose or e["name"] not in BOILERPLATES],
            "recovered_envs": self.recovered_envs,
            "relationships": self.relationships,
            "call_graph": self.call_graph,
            "functions": list(reported_funcs.values())
        }

    def _analyze_elf(self):
        try:
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                
                # Cache section mapping
                exec_secs = []
                for sec in elf.iter_sections():
                    self.sections_map.append({
                        "name": sec.name,
                        "sh_addr": sec['sh_addr'],
                        "sh_size": sec['sh_size'],
                        "sh_offset": sec['sh_offset']
                    })
                    if sec['sh_flags'] & 4:  # SHF_EXECINSTR
                        exec_secs.append((sec['sh_addr'], sec['sh_addr'] + sec['sh_size']))
                    
                    # Extract dependencies
                    if isinstance(sec, DynamicSection):
                        for tag in sec.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                self.dependencies.append(tag.needed)
                                self.relationships.append(f"{os.path.basename(self.filepath)} imports {tag.needed}")

                    # Read relocations
                    if isinstance(sec, RelocationSection):
                        symtable = elf.get_section(sec['sh_link'])
                        for rel in sec.iter_relocations():
                            symbol = symtable.get_symbol(rel['r_info_sym'])
                            if symbol.name:
                                self.relocs[rel['r_offset']] = symbol.name

                # Read symbols (.symtab & .dynsym)
                for sec_name in [".symtab", ".dynsym"]:
                    sec = elf.get_section_by_name(sec_name)
                    if sec:
                        for sym in sec.iter_symbols():
                            name = sym.name
                            if not name:
                                continue
                                
                            is_exec = any(start <= sym['st_value'] < end for start, end in exec_secs)
                            is_func = (sym['st_info']['type'] == 'STT_FUNC') or (is_exec and sym['st_info']['type'] == 'STT_NOTYPE')
                            is_defined = sym['st_shndx'] != 'SHN_UNDEF'
                            
                            if is_func:
                                if is_defined:
                                    if name in BOILERPLATES and not self.verbose:
                                        continue
                                    self.functions[sym['st_value']] = {
                                        "name": name,
                                        "addr": sym['st_value'],
                                        "size": sym['st_size'],
                                        "score": 0,
                                        "reasons": []
                                    }
                                    # Check if exported (Global/Weak binding and defined)
                                    if sym['st_info']['bind'] != 'STB_LOCAL':
                                        self.exports.append({
                                            "name": name,
                                            "addr": hex(sym['st_value']),
                                            "priority": "High" if any(k in name.lower() for k in ["message", "satellite", "auth", "flag", "check"]) else "Medium"
                                        })
                                        self.relationships.append(f"{os.path.basename(self.filepath)} exports {name}")
                                else:
                                    # Imported function
                                    self.imports[sym['st_value']] = name
        except Exception:
            pass

    def _analyze_pe(self):
        try:
            pe = pefile.PE(self.filepath)
            
            # Map sections
            for sec in pe.sections:
                self.sections_map.append({
                    "name": sec.Name.decode("utf-8", errors="ignore").strip("\x00"),
                    "sh_addr": pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress,
                    "sh_size": sec.Misc_VirtualSize,
                    "sh_offset": sec.PointerToRawData
                })

            # Dependencies
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    self.dependencies.append(dll_name)
                    self.relationships.append(f"{os.path.basename(self.filepath)} imports {dll_name}")
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode("utf-8", errors="ignore")
                            self.imports[imp.address] = name

            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"ordinal_{exp.ordinal}"
                    if name in BOILERPLATES and not self.verbose:
                        continue
                    addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
                    self.exports.append({
                        "name": name,
                        "addr": hex(addr),
                        "priority": "High"
                    })
                    self.relationships.append(f"{os.path.basename(self.filepath)} exports {name}")
                    self.functions[addr] = {
                        "name": name,
                        "addr": addr,
                        "size": 0,
                        "score": 0,
                        "reasons": []
                    }
                    
            pe.close()
        except Exception:
            pass

    def _discover_functions_heuristically(self):
        """Scans code segments for standard function prologues to identify functions in stripped binaries."""
        for sec in self.sections_map:
            # Check if name is .text or code segment
            if sec["name"] in (".text", "code") or "exec" in sec["name"]:
                start_offset = sec["sh_offset"]
                end_offset = start_offset + sec["sh_size"]
                code = self.file_bytes[start_offset:end_offset]
                
                # Heuristic patterns for function prologues (x86_64 and x86)
                patterns = [
                    (b"\xf3\x0f\x1e\xfa", 0),
                    (b"\x55\x48\x89\xe5", 0),
                    (b"\x55\x89\xe5", 0)
                ]
                
                for pat, offset_adj in patterns:
                    for match in re.finditer(re.escape(pat), code):
                        va = sec["sh_addr"] + match.start() + offset_adj
                        if va not in self.functions:
                            name = f"FUN_{va:08x}"
                            if name in BOILERPLATES and not self.verbose:
                                continue
                            self.functions[va] = {
                                "name": name,
                                "addr": va,
                                "size": 0,
                                "score": 0,
                                "reasons": []
                            }

    def _get_string_at_va(self, va: int) -> Optional[str]:
        for sec in self.sections_map:
            start = sec['sh_addr']
            end = start + sec['sh_size']
            if start <= va < end:
                offset = sec['sh_offset'] + (va - start)
                res = bytearray()
                while offset < len(self.file_bytes) and self.file_bytes[offset] != 0:
                    res.append(self.file_bytes[offset])
                    offset += 1
                return res.decode('utf-8', errors='ignore')
        return None

    def _resolve_plt_target(self, target_va: int) -> Optional[str]:
        if target_va in self.plt_map:
            return self.plt_map[target_va]
            
        code_bytes = b""
        for sec in self.sections_map:
            if sec['sh_addr'] <= target_va < sec['sh_addr'] + sec['sh_size']:
                offset = sec['sh_offset'] + (target_va - sec['sh_addr'])
                code_bytes = self.file_bytes[offset:offset+16]
                break
                
        if not code_bytes:
            return None
            
        cs_mode = CS_MODE_64 if "64" in str(self.bitness) else CS_MODE_32
        try:
            cs = Cs(CS_ARCH_X86, cs_mode)
            instructions = list(cs.disasm(code_bytes, target_va))
            if instructions:
                insn = instructions[0]
                if insn.mnemonic == "jmp" and "rip" in insn.op_str:
                    match = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]', insn.op_str)
                    if match:
                        sign, val_str = match.group(1), match.group(2)
                        val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                        got_addr = insn.address + insn.size + (val if sign == "+" else -val)
                        if got_addr in self.relocs:
                            name = self.relocs[got_addr]
                            self.plt_map[target_va] = name
                            return name
        except Exception:
            pass
        return None

    def _disassemble_and_analyze_functions(self):
        cs_mode = CS_MODE_64 if "64" in str(self.bitness) else CS_MODE_32
        try:
            cs = Cs(CS_ARCH_X86, cs_mode)
        except Exception:
            return

        # Seed ELF / PE Entry point as function
        entry_addr = None
        if self.format == "ELF":
            try:
                with open(self.filepath, "rb") as f:
                    elf = ELFFile(f)
                    entry_addr = elf.header.e_entry
            except Exception:
                pass
        elif self.format == "PE":
            try:
                pe = pefile.PE(self.filepath)
                entry_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
                pe.close()
            except Exception:
                pass

        if entry_addr and entry_addr not in self.functions:
            self.functions[entry_addr] = {
                "name": "_start" if self.verbose else "FUN_entry",
                "addr": entry_addr,
                "size": 0,
                "score": 0,
                "reasons": []
            }

        # Discover functions from prologues
        self._discover_functions_heuristically()

        # Build executable address ranges for call validation
        exec_ranges = []
        for sec in self.sections_map:
            if sec["name"] in (".text", "code") or "exec" in sec["name"]:
                exec_ranges.append((sec["sh_addr"], sec["sh_addr"] + sec["sh_size"]))

        # Perform recursive function discovery worklist
        analyzed_vas = set()
        worklist = list(self.functions.keys())

        while worklist:
            va = worklist.pop(0)
            if va in analyzed_vas:
                continue
            analyzed_vas.add(va)

            func = self.functions[va]
            code_bytes = b""
            for sec in self.sections_map:
                if sec['sh_addr'] <= va < sec['sh_addr'] + sec['sh_size']:
                    sh_offset = sec['sh_offset'] + (va - sec['sh_addr'])
                    size = func["size"] if func["size"] > 0 else 4096
                    code_bytes = self.file_bytes[sh_offset:sh_offset+size]
                    break

            if not code_bytes:
                continue

            instructions = []
            try:
                for insn in cs.disasm(code_bytes, va):
                    instructions.append(insn)
                    if insn.mnemonic in ("ret", "jmp") and insn.op_str == "":
                        break
                    if insn.mnemonic == "jmp":
                        try:
                            target = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                            if func["size"] > 0 and (target < va or target >= va + func["size"]):
                                break
                        except ValueError:
                            pass
            except Exception:
                pass

            func["instructions"] = instructions
            func["calls"] = []

            # Scoring heuristics and call analysis
            score = 0
            reasons = []

            for idx, insn in enumerate(instructions):
                target_name = ""
                # 1. Recover calls
                if insn.mnemonic == "call":
                    try:
                        target_va = int(insn.op_str, 16) if insn.op_str.startswith("0x") else int(insn.op_str)
                        if target_va in self.functions:
                            target_name = self.functions[target_va]["name"]
                        elif target_va in self.imports:
                            target_name = self.imports[target_va]
                        else:
                            resolved = self._resolve_plt_target(target_va)
                            if resolved:
                                target_name = resolved
                            else:
                                is_exec = any(start <= target_va < end for start, end in exec_ranges)
                                if is_exec:
                                    target_name = f"FUN_{target_va:08x}"
                                    if target_va not in self.functions:
                                        self.functions[target_va] = {
                                            "name": target_name,
                                            "addr": target_va,
                                            "size": 0,
                                            "score": 0,
                                            "reasons": []
                                        }
                                        worklist.append(target_va)
                    except ValueError:
                        if "rip" in insn.op_str:
                            match = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]', insn.op_str)
                            if match:
                                sign, val_str = match.group(1), match.group(2)
                                val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                                iat_addr = insn.address + insn.size + (val if sign == "+" else -val)
                                if iat_addr in self.imports:
                                    target_name = self.imports[iat_addr]
                        else:
                            target_name = insn.op_str

                    if target_name:
                        if not (target_name in BOILERPLATES and not self.verbose):
                            func["calls"].append(target_name)

                        # High value targets and scores
                        t_lower = target_name.lower()
                        if any(api in t_lower for api in ["mmap", "mprotect", "virtualprotect", "virtualalloc"]):
                            score += 45
                            reasons.append("Allocates or protects executable memory (mmap/mprotect/VirtualAlloc)")
                        elif "getenv" in t_lower:
                            score += 30
                            reasons.append("Reads environment variable configuration (getenv)")
                        elif any(api in t_lower for api in ["memfrob", "crypt", "decrypt", "encrypt", "aes", "rc4", "chacha", "md5", "sha"]):
                            score += 40
                            reasons.append("Implements cryptographic/obfuscation routines (crypto APIs)")
                        elif any(api in t_lower for api in ["strcmp", "memcmp", "strncmp"]):
                            score += 25
                            reasons.append("Executes string/data comparisons (strcmp/memcmp)")
                        elif "ptrace" in t_lower:
                            score += 45
                            reasons.append("Evasion control detects debuggers (ptrace)")
                        elif any(api in t_lower for api in ["dlopen", "dlsym"]):
                            score += 35
                            reasons.append("Imports dynamic libraries at runtime (dlopen/dlsym)")
                        elif "memcpy" in t_lower:
                            score += 15
                            reasons.append("Performs bulk memory copies (memcpy)")

                # Environment Variable recovery
                if insn.mnemonic == "call" and target_name and "getenv" in target_name.lower():
                    # Backtrack 10 instructions to locate the RDI register argument loading
                    arg_reg = "rdi"
                    for back_idx in range(1, 11):
                        if idx - back_idx >= 0:
                            prev_insn = instructions[idx - back_idx]
                            if prev_insn.mnemonic == "mov" and prev_insn.op_str.startswith("rdi,"):
                                src = prev_insn.op_str.split(",")[1].strip()
                                arg_reg = src
                            if prev_insn.mnemonic == "lea" and prev_insn.op_str.startswith(arg_reg + ","):
                                match = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]', prev_insn.op_str)
                                if match:
                                    sign, val_str = match.group(1), match.group(2)
                                    val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
                                    target_str_va = prev_insn.address + prev_insn.size + (val if sign == "+" else -val)
                                    env_var = self._get_string_at_va(target_str_va)
                                    if env_var:
                                        self.recovered_envs.append({
                                            "func": func["name"],
                                            "var": env_var,
                                            "confidence": "High"
                                        })
                                        break

                # Self-modifying/XOR logic detection inside instructions
                if insn.mnemonic == "xor" and "," in insn.op_str:
                    regs = insn.op_str.split(",")
                    if len(regs) == 2 and regs[0].strip() != regs[1].strip():
                        score += 15
                        reasons.append("XOR-based encryption loops")

            # Score adjustments based on functions exports or central names
            is_exported = any(int(exp["addr"], 16) == va for exp in self.exports if exp.get("addr"))
            if is_exported:
                score += 20
                reasons.append("Exported API")

            if func["name"] in ("main", "send_satellite_message"):
                score += 25
                reasons.append("Central execution path")

            func["score"] = score
            func["reasons"] = list(set(reasons))

        # Pass 2: Score propagation along calling paths (2 levels)
        for _ in range(2):
            for va, func in list(self.functions.items()):
                for target_name in func.get("calls", []):
                    target_func = next((f for f in self.functions.values() if f["name"] == target_name), None)
                    if target_func and target_func.get("score", 0) > 0:
                        added_score = int(target_func["score"] * 0.4)
                        if added_score > 0:
                            func["score"] = func.get("score", 0) + added_score
                            reason_msg = f"Calls suspicious function {target_name}"
                            if reason_msg not in func["reasons"]:
                                func["reasons"].append(reason_msg)

    def _build_call_graph(self):
        """Builds call graph starting from export functions or main."""
        for va, func in self.functions.items():
            if func.get("calls"):
                filtered_calls = [c for c in func["calls"] if self.verbose or c not in BOILERPLATES]
                if filtered_calls:
                    self.call_graph[func["name"]] = list(set(filtered_calls))
