import re
from typing import Dict, Any, List

class PayloadDetector:
    """Analyzes runtime traces to detect hidden payloads and executable regions."""

    def __init__(self, trace_data: Dict[str, Any]):
        self.trace_data = trace_data

    def detect(self) -> Dict[str, Any]:
        """Analyzes strace and ltrace for payload indicators."""
        evidence = []
        exec_ranges = []
        
        # 1. Parse strace events
        strace_events = self.trace_data.get("strace", {}).get("events", [])
        for ev in strace_events:
            raw = ev["raw"]
            if ev["type"] == "mmap_exec":
                addr_match = re.search(r'=\s*(0x[0-9a-fA-F]+)', raw)
                size_match = re.search(r'mmap\([^\,]*,\s*([0-9a-fA-Fx]+)', raw)
                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    size = 4096
                    if size_match:
                        try:
                            sz_str = size_match.group(1)
                            size = int(sz_str, 16) if sz_str.startswith("0x") else int(sz_str)
                        except ValueError:
                            pass
                    exec_ranges.append((addr, addr + size))
                    evidence.append("mmap executable memory")
            elif ev["type"] == "mprotect_exec":
                addr_match = re.search(r'mprotect\(\s*(0x[0-9a-fA-F]+)', raw)
                size_match = re.search(r'mprotect\(\s*0x[0-9a-fA-F]+,\s*([0-9a-fA-Fx]+)', raw)
                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    size = 4096
                    if size_match:
                        try:
                            sz_str = size_match.group(1)
                            size = int(sz_str, 16) if sz_str.startswith("0x") else int(sz_str)
                        except ValueError:
                            pass
                    exec_ranges.append((addr, addr + size))
                    evidence.append("mprotect executable memory")

        # 2. Parse ltrace calls
        ltrace_calls = self.trace_data.get("ltrace", {}).get("calls", [])
        for c in ltrace_calls:
            raw = c["raw"]
            if "mmap" in raw and any(x in raw for x in ["0b111", ", 7,", ", 7)", "PROT_EXEC"]):
                addr_match = re.search(r'=\s*(0x[0-9a-fA-F]+)', raw)
                size_match = re.search(r'mmap\w*\([^\,]*,\s*([0-9a-fA-Fx]+)', raw)
                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    size = 4096
                    if size_match:
                        try:
                            sz_str = size_match.group(1)
                            size = int(sz_str, 16) if sz_str.startswith("0x") else int(sz_str)
                        except ValueError:
                            pass
                    exec_ranges.append((addr, addr + size))
                    evidence.append("mmap executable memory")
            elif "mprotect" in raw and any(x in raw for x in ["0b111", ", 7,", ", 7)", "PROT_EXEC"]):
                addr_match = re.search(r'mprotect\w*\(\s*(0x[0-9a-fA-F]+)', raw)
                size_match = re.search(r'mprotect\w*\(\s*0x[0-9a-fA-F]+,\s*([0-9a-fA-Fx]+)', raw)
                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    size = 4096
                    if size_match:
                        try:
                            sz_str = size_match.group(1)
                            size = int(sz_str, 16) if sz_str.startswith("0x") else int(sz_str)
                        except ValueError:
                            pass
                    exec_ranges.append((addr, addr + size))
                    evidence.append("mprotect executable memory")

        # 3. Detect memcpy into executable memory
        for c in ltrace_calls:
            raw = c["raw"]
            if "memcpy" in raw:
                match = re.search(r'memcpy\w*\(\s*(0x[0-9a-fA-F]+)', raw)
                if match:
                    dst = int(match.group(1), 16)
                    is_in_exec = any(start <= dst < end for start, end in exec_ranges)
                    if is_in_exec:
                        evidence.append("memcpy into executable region")

        # Deduplicate evidence
        evidence = list(set(evidence))
        
        return {
            "hidden_payload_detected": len(evidence) > 0,
            "evidence": evidence
        }
