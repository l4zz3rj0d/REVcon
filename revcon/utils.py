import subprocess
import shutil
import sys
from typing import List, Tuple
from revcon.banner import C, _no_color

def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Runs a system command and returns exit code, stdout, and stderr."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def has_cmd(cmd: str) -> bool:
    """Checks if a command is available on the system PATH."""
    return shutil.which(cmd) is not None

def log_verbose(msg: str, verbose: bool = False) -> None:
    """Prints a message if verbose mode is enabled."""
    if verbose:
        nc = _no_color()
        if nc:
            print(f"[DEBUG] {msg}")
        else:
            print(f"{C.GR}[DEBUG] {msg}{C.RST}")

def log_info(msg: str) -> None:
    """Prints a standard info message."""
    nc = _no_color()
    if nc:
        print(f"[*] {msg}")
    else:
        print(f"{C.CY}[*]{C.RST} {C.W}{msg}{C.RST}")

def log_success(msg: str) -> None:
    """Prints a success message."""
    nc = _no_color()
    if nc:
        print(f"[+] {msg}")
    else:
        print(f"{C.G}{C.B}[+]{C.RST} {C.GD}{msg}{C.RST}")

def log_warn(msg: str) -> None:
    """Prints a warning message."""
    nc = _no_color()
    if nc:
        print(f"[!] {msg}")
    else:
        print(f"{C.Y}{C.B}[!]{C.RST} {C.Y}{msg}{C.RST}")

def log_err(msg: str) -> None:
    """Prints an error message to stderr."""
    nc = _no_color()
    if nc:
        print(f"[-] {msg}", file=sys.stderr)
    else:
        print(f"{C.R}{C.B}[-]{C.RST} {C.R}{msg}{C.RST}", file=sys.stderr)
