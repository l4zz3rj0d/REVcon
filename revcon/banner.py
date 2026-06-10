"""
  REVcon  v1.0.0  —  Automated Binary Reconnaissance Engine

  Static Recon | ELF / PE / Mach-O | Heuristics | Challenge Predictor

Dependencies:
  pip install colorama capstone pyelftools pefile macholib
"""

import os
import sys

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

VERSION      = "1.0.0"
__author__   = "Sree Danush S (L4ZZ3RJ0D)"
__license__  = "MIT"
__credits__  = ["L4ZZ3RJ0D"]
__maintainer__ = "L4ZZ3RJ0D"

# ══════════════════════════════════════════════════════════════════════
# TERMINAL COLOURS
# ══════════════════════════════════════════════════════════════════════

class C:
    R   = "\033[91m"    # bright red
    RD  = "\033[31m"    # dark red
    G   = "\033[92m"    # bright green
    GD  = "\033[32m"    # dark green
    Y   = "\033[93m"    # yellow
    O   = "\033[38;5;208m"  # orange
    CY  = "\033[96m"    # bright cyan
    CYD = "\033[36m"    # dim cyan
    BL  = "\033[94m"    # blue
    MG  = "\033[95m"    # magenta
    W   = "\033[97m"    # white
    GR  = "\033[90m"    # grey
    GL  = "\033[37m"    # light grey
    B   = "\033[1m"     # bold
    DIM = "\033[2m"
    RST = "\033[0m"     # reset

def _no_color() -> bool:
    return not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))

def _strip(s: str) -> str:
    import re
    return re.sub(r'\033\[[^m]*m', '', s)

# ══════════════════════════════════════════════════════════════════════
# BANNER  — cyan ASCII art
# ══════════════════════════════════════════════════════════════════════

_BANNER_ART = r"""
     _____        ______    ____      ____       _____           _____  _____   ______   
 ___|\    \   ___|\     \  |    |    |    |  ___|\    \     ____|\    \|\    \ |\     \  
|    |\    \ |     \     \ |    |    |    | /    /\    \   /     /\    \\    \| \     \ 
|    | |    ||     ,_____/||    |    |    ||    |  |    | /     /  \    \\|    \  \     |
|    |/____/ |     \--'\_|/|    |    |    ||    |  |____||     |    |    ||     \  |    |
|    |\    \ |     /___/|  |    |    |    ||    |   ____ |     |    |    ||      \ |    |
|    | |    ||     \____|\ |\    \  /    /||    |  |    ||\     \  /    /||    |\ \|    |
|____| |____||____ '     /|| \ ___\/___ / ||\ ___\/    /|| \_____\/____/ ||____||\_____/|
|    | |    ||    /_____/ | \ |   ||   | / | |   /____/ | \ |    ||    | /|    |/ \|   ||
|____| |____||____|     | /  \|___||___|/   \|___|    | /  \|____||____|/ |____|   |___|/
  \(     )/    \( |_____|/     \(    )/       \( |____|/      \(    )/      \(       )/  
   '     '      '    )/         '    '         '   )/          '    '        '       '   
                     '                             '                                     """

_BANNER_CREDIT = "                            [ Created by L4ZZ3RJ0D — @l4zz3rj0d ]"

_BANNER_SUB = "               v{ver}  │  Binary Recon Engine  │  Static Intelligence Framework"

def print_banner():
    if _no_color():
        print(f"  REVcon v{VERSION}  —  Binary Recon Engine")
        print(f"  {_BANNER_CREDIT.strip()}\n")
        return
    print(f"{C.CY}{C.B}{_BANNER_ART}{C.RST}")
    print()
    print(f"{C.W}{_BANNER_CREDIT}{C.RST}")
    print()
    print(f"{C.CYD}{_BANNER_SUB.format(ver=VERSION)}{C.RST}\n")
