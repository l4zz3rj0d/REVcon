from typing import Dict, Any, List

class EducationalGuidance:
    """Generates the Investigation Priority Roadmap based on detected surfaces."""

    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    def generate_roadmap(self) -> List[str]:
        """Generates the Investigation Priority sequence based on highest priority findings."""
        roadmap = []
        step_num = 1
        
        payload = self.metadata.get("runtime_payload", {})
        if payload.get("hidden_payload_detected"):
            roadmap.append(f"{step_num}. Analyze runtime loader and dynamic memory allocation")
            step_num += 1
            
        ranked_functions = self.metadata.get("ranked_functions", [])
        if ranked_functions:
            top_func = ranked_functions[0]
            if "crypto" in "".join(top_func["reasons"]):
                roadmap.append(f"{step_num}. Analyze crypto usage in {top_func['name']}")
                step_num += 1
            elif "validation" in "".join(top_func["reasons"]):
                roadmap.append(f"{step_num}. Analyze suspicious validation routine in {top_func['name']}")
                step_num += 1
            else:
                roadmap.append(f"{step_num}. Analyze high-priority function {top_func['name']}")
                step_num += 1
                
        runtime = self.metadata.get("runtime_tracer", {})
        anti_debug = any(e["type"] == "ptrace" for e in runtime.get("strace", {}).get("events", []))
        if anti_debug:
            roadmap.append(f"{step_num}. Analyze anti-debug logic (ptrace bypass)")
            step_num += 1
            
        imports = self.metadata.get("imports", {}).get("flagged_imports", {})
        if imports:
            roadmap.append(f"{step_num}. Analyze dynamic imports and external API usage")
            step_num += 1
            
        if len(roadmap) == 0:
            roadmap.append(f"{step_num}. Begin static analysis on entry point")
            
        return roadmap

    def generate_scorecard(self) -> Dict[str, str]:
        """Deprecated in vNext Strategic Redesign. Keeping for backwards compatibility if needed."""
        return {}
