from typing import Dict, Any, List

class EducationalGuidance:
    """Maps technical findings to beginner-friendly explanations and roadmaps."""

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    def generate_roadmap(self) -> List[str]:
        """Generates the RE Roadmap sequence."""
        roadmap = []
        step_num = 1
        
        # Static
        roadmap.append(f"{step_num}. Inspect imported libraries and strings for basic context")
        step_num += 1
        
        # Runtime / Unpacking
        payload = self.metadata.get("runtime_payload", {})
        if payload.get("hidden_payload_detected"):
            roadmap.append(f"{step_num}. Dump hidden payload mapped at runtime")
            step_num += 1
            
        # Validator
        heuristics = self.metadata.get("heuristics", {})
        if heuristics.get("validators") or heuristics.get("per_character_validation"):
            roadmap.append(f"{step_num}. Analyze validator loop and recover comparison logic")
            step_num += 1
            
        # Constant Reconstruction
        emulation = self.metadata.get("emulation", {}).get("reconstructed_buffers", [])
        if emulation:
            roadmap.append(f"{step_num}. Examine reconstructed stack strings and constants")
            step_num += 1
            
        # Flag
        if self.metadata.get("flag_intel") and self.metadata["flag_intel"].get("matches"):
            roadmap.append(f"{step_num}. Recover full flag from memory")
            step_num += 1
            
        if len(roadmap) == 1:
            roadmap.append(f"{step_num}. Disassemble the main function and trace execution")
            
        return roadmap

    def generate_scorecard(self) -> Dict[str, str]:
        """Generates the RE Scorecard."""
        payload = self.metadata.get("runtime_payload", {})
        heuristics = self.metadata.get("heuristics", {})
        tracer = self.metadata.get("runtime_tracer", {})
        
        complexity = "Low"
        obfuscation = "Low"
        packing = "Not Detected"
        hidden_payload = "Not Detected"
        validator = "Not Detected"
        diff = "Beginner"
        
        if tracer.get("strace", {}).get("events"):
            complexity = "Medium"
            
        if payload.get("hidden_payload_detected"):
            packing = "Detected"
            hidden_payload = "Detected"
            obfuscation = "High"
            complexity = "High"
            diff = "Advanced"
            
        if heuristics.get("validators") or heuristics.get("per_character_validation"):
            validator = "Detected"
            if diff == "Beginner":
                diff = "Intermediate"
                
        return {
            "Runtime Complexity": complexity,
            "Obfuscation": obfuscation,
            "Packing": packing,
            "Hidden Payload": hidden_payload,
            "Validator": validator,
            "Estimated Difficulty": diff,
            "Recommended Tool": "Ghidra / IDA Pro" if diff in ("Beginner", "Intermediate") else "x64dbg / GDB / Unicorn"
        }
