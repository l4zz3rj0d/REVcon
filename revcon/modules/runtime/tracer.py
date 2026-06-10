import subprocess
import os
import tempfile
from typing import Dict, Any, List, Optional

class RuntimeTracer:
    """Executes the binary under strace and ltrace to collect dynamic events."""

    def __init__(self, filepath: str, timeout: int = 5, env_vars: Optional[Dict[str, str]] = None):
        self.filepath = filepath
        self.timeout = timeout
        self.env_vars = env_vars or {}

    def trace(self) -> Dict[str, Any]:
        """Runs the traces and returns the collected data."""
        results = {
            "strace": self._run_strace(),
            "ltrace": self._run_ltrace()
        }
        return results

    def _run_strace(self) -> Dict[str, Any]:
        """Runs strace filtering for memory, process, and network events."""
        # mmap, mprotect, ptrace, fork, execve, socket, connect, getenv
        trace_events = "mmap,mprotect,ptrace,fork,clone,execve,socket,connect"
        
        # We write dummy input in case the binary blocks on stdin
        dummy_input = b"A" * 100 + b"\n"
        
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
                log_file = f.name
            
            cmd = ["strace", "-f", "-e", f"trace={trace_events}", "-o", log_file, self.filepath]
            
            env = os.environ.copy()
            if self.env_vars:
                env.update(self.env_vars)
            binary_dir = os.path.dirname(os.path.abspath(self.filepath))
            env["LD_LIBRARY_PATH"] = f"{binary_dir}:{env.get('LD_LIBRARY_PATH', '')}"
            
            # Run the process
            proc = subprocess.run(
                cmd, 
                input=dummy_input,
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                cwd=binary_dir,
                env=env,
                timeout=self.timeout
            )
            
            with open(log_file, "r") as f:
                lines = f.readlines()
                
            os.remove(log_file)
            return self._parse_strace(lines)
            
        except subprocess.TimeoutExpired:
            # We still want to parse whatever was written before timeout
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()
                os.remove(log_file)
                return self._parse_strace(lines)
            except:
                return {"events": [], "error": "Timeout and failed to read log"}
        except Exception as e:
            return {"events": [], "error": str(e)}

    def _parse_strace(self, lines: List[str]) -> Dict[str, Any]:
        """Parses strace output to extract meaningful events."""
        parsed_events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Example: 1234  mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7ff0000
            if "mmap(" in line and "PROT_EXEC" in line:
                parsed_events.append({"type": "mmap_exec", "raw": line})
            elif "mprotect(" in line and "PROT_EXEC" in line:
                parsed_events.append({"type": "mprotect_exec", "raw": line})
            elif "ptrace(" in line:
                parsed_events.append({"type": "ptrace", "raw": line})
            elif "fork(" in line or "clone(" in line:
                parsed_events.append({"type": "fork", "raw": line})
            elif "execve(" in line:
                parsed_events.append({"type": "execve", "raw": line})
            elif "socket(" in line or "connect(" in line:
                parsed_events.append({"type": "network", "raw": line})
                
        return {"events": parsed_events}

    def _run_ltrace(self) -> Dict[str, Any]:
        """Runs ltrace to detect library calls and potential hooks."""
        dummy_input = b"A" * 100 + b"\n"
        
        try:
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
                log_file = f.name
            
            # Trace library internal calls (-x "*") and trace child processes (-f)
            cmd = ["ltrace", "-f", "-x", "*", "-o", log_file, self.filepath]
            
            env = os.environ.copy()
            if self.env_vars:
                env.update(self.env_vars)
            binary_dir = os.path.dirname(os.path.abspath(self.filepath))
            env["LD_LIBRARY_PATH"] = f"{binary_dir}:{env.get('LD_LIBRARY_PATH', '')}"
            
            proc = subprocess.run(
                cmd, 
                input=dummy_input,
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                cwd=binary_dir,
                env=env,
                timeout=self.timeout
            )
            
            with open(log_file, "r") as f:
                lines = f.readlines()
                
            os.remove(log_file)
            return self._parse_ltrace(lines)
            
        except subprocess.TimeoutExpired:
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()
                os.remove(log_file)
                return self._parse_ltrace(lines)
            except:
                return {"calls": [], "error": "Timeout and failed to read log"}
        except Exception as e:
            return {"calls": [], "error": str(e)}

    def _parse_ltrace(self, lines: List[str]) -> Dict[str, Any]:
        """Parses ltrace output to find unusual calls or hooks."""
        calls = []
        for line in lines:
            line = line.strip()
            if not line or "---" in line or "+++" in line:
                continue
            
            # Simple extraction for now
            if "(" in line:
                func_name = line.split("(")[0].strip()
                # Basic check for getenv which was requested
                if func_name == "getenv":
                    calls.append({"func": "getenv", "raw": line})
                else:
                    calls.append({"func": func_name, "raw": line})
                    
        return {"calls": calls}
