import sys
from colorama import Fore, Style

def print_banner() -> None:
    """Prints a styled ASCII art banner for REVcon."""
    banner = fr"""{Fore.CYAN}
  _____  _______      _______
 |  __ \|  ____\ \    / / ____|
 | |__) | |__   \ \  / / |
 |  _  /|  __|   \ \/ /| |
 | | \ \| |____   \  / | |____
 |_|  \_\______|   \/   \_____|
{Fore.GREEN}
  Reverse Engineering Recon Framework | v1.0.0
  Author: Lazzer
====================================================={Style.RESET_ALL}"""
    print(banner)
