from typing import Dict, Any, List
import re

class PayloadDetector:
    """Analyzes runtime traces to detect hidden payloads and executable regions."""

    def __init__(self, trace_data: Dict[str, Any]):
        self.trace_data = trace_data

    def detect(self) -> Dict[str, Any]:
        """Analyzes strace and ltrace for payload indicators."""
        findings = []
        
        strace_events = self.trace_data.get("strace", {}).get("events", [])
        
        # Detect mmap PROT_EXEC
        mmap_execs = [e for e in strace_events if e["type"] == "mmap_exec"]
        if mmap_execs:
            for ev in mmap_execs:
                # Attempt to extract address
                # Example: ... = 0x7ffff7ff0000
                addr_match = re.search(r'=\s*(0x[0-9a-fA-F]+)', ev["raw"])
                addr = addr_match.group(1) if addr_match else "Unknown"
                
                findings.append({
                    "indicator": "mmap_exec",
                    "description": "Allocated new executable memory",
                    "address": addr,
                    "confidence": "High",
                    "raw": ev["raw"]
                })
                
        # Detect mprotect PROT_EXEC
        mprotect_execs = [e for e in strace_events if e["type"] == "mprotect_exec"]
        if mprotect_execs:
            for ev in mprotect_execs:
                addr_match = re.search(r'mprotect\((0x[0-9a-fA-F]+)', ev["raw"])
                addr = addr_match.group(1) if addr_match else "Unknown"
                
                findings.append({
                    "indicator": "mprotect_exec",
                    "description": "Changed memory permissions to executable (often unpacking)",
                    "address": addr,
                    "confidence": "High",
                    "raw": ev["raw"]
                })
                
        return {
            "hidden_payload_detected": len(findings) > 0,
            "payload_findings": findings
        }
