import subprocess
import shutil
import sys
from typing import List, Tuple
from colorama import Fore, Style

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
        print(f"{Fore.BLACK}{Style.BRIGHT}[DEBUG] {msg}{Style.RESET_ALL}")

def log_info(msg: str) -> None:
    """Prints a standard info message."""
    print(f"[*] {msg}")

def log_success(msg: str) -> None:
    """Prints a success message."""
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

def log_warn(msg: str) -> None:
    """Prints a warning message."""
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def log_err(msg: str) -> None:
    """Prints an error message to stderr."""
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}", file=sys.stderr)
