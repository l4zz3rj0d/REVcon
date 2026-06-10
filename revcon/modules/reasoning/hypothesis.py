from typing import Dict, Any, List

class HypothesisEngine:
    """Aggregates all findings to generate automated hypotheses about the binary's behavior."""

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    def generate(self) -> List[Dict[str, Any]]:
        hypotheses = []
        
        # 1. Unpacker Hypothesis
        payload_intel = self.metadata.get("runtime_payload", {})
        entropy_intel = self.metadata.get("entropy", {})
        heuristics = self.metadata.get("heuristics", {})
        
        if payload_intel.get("hidden_payload_detected"):
            confidence = 95
            evidence = []
            if payload_intel.get("payload_findings"):
                evidence.append(payload_intel["payload_findings"][0]["indicator"])
            if entropy_intel.get("has_high_entropy"):
                evidence.append("High section entropy")
                
            hypotheses.append({
                "description": "Runtime unpacker detected",
                "confidence": confidence,
                "evidence": evidence,
                "recommendation": "Dump executable memory after decryption or analyze extracted payloads."
            })
            
        # 2. Hidden Validator Hypothesis
        if heuristics.get("per_character_validation") or heuristics.get("validators"):
            confidence = 92
            evidence = []
            if heuristics.get("validators"):
                evidence.extend(heuristics["validators"])
            if heuristics.get("per_character_validation"):
                evidence.append("Per-character validation loop")
                
            hypotheses.append({
                "description": "Hidden validator present",
                "confidence": confidence,
                "evidence": evidence,
                "recommendation": "Recover validation table or analyze comparison instructions."
            })
            
        # 3. GOT Hook / Anti-Analysis
        strace_events = self.metadata.get("runtime_tracer", {}).get("strace", {}).get("events", [])
        anti_debug = [e for e in strace_events if e["type"] == "ptrace"]
        if anti_debug:
            hypotheses.append({
                "description": "Anti-debugging / ptrace logic detected",
                "confidence": 99,
                "evidence": ["ptrace() call observed at runtime"],
                "recommendation": "Patch ptrace call or use a stealth debugger/anti-anti-debug plugin."
            })
            
        return hypotheses
