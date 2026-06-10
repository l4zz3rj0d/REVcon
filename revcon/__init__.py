"""
  REVcon  v1.0.0  —  Automated Binary Reconnaissance Engine

  Static Recon | ELF / PE / Mach-O | Heuristics | Challenge Predictor

  Author: Sree Danush S (L4ZZ3RJ0D)
"""

import argparse
import sys
import os

from revcon.banner import print_banner, C, VERSION, _no_color
from revcon.engine import AnalysisEngine
from revcon.report import ReportGenerator


def _build_parser() -> argparse.ArgumentParser:
    """Constructs the CLI argument parser with Spider-style grouped sections."""
    p = argparse.ArgumentParser(
        prog="revcon",
        description=(
            f"{C.R}{C.B}REVcon v{VERSION}{C.RST}  —  "
            "Automated Binary Reconnaissance & Triage Framework"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"\n{C.GR}  ── Examples ────────────────────────────────────────────────────\n\n"
            f"{C.R}  revcon chall.bin\n"
            f"  revcon crackme -q\n"
            f"  revcon target.exe -j > intel.json\n"
            f"  revcon challenge -F \"HTB{{}}\"\n"
            f"  revcon binary -F \"DUCTF{{}}\" -v\n"
            f"  revcon packed.bin -q -F \"FLAG{{}}\"\n"
            f"\n  For authorized security research and education only.{C.RST}\n"
        ),
    )

    p.add_argument("binary", nargs="?", help="Path to the binary file to analyze")

    scan = p.add_argument_group(f"{C.R}Scan Options{C.RST}")
    scan.add_argument(
        "--quick", "-q", action="store_true",
        help="Skip Capstone disassembly heuristics and entropy analysis"
    )
    scan.add_argument(
        "--dynamic", "-D", action="store_true",
        help="Enable runtime analysis (strace/ltrace/LD_DEBUG). WARNING: Executes the binary!"
    )
    scan.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging / debug output"
    )

    out = p.add_argument_group(f"{C.R}Output{C.RST}")
    out.add_argument(
        "--json", "-j", action="store_true",
        help="Output full findings as raw JSON to stdout"
    )
    out.add_argument(
        "--dump", "-d", action="store_true",
        help="Automatically dump extracted payloads to disk if detected at runtime"
    )

    intel = p.add_argument_group(f"{C.R}Intelligence{C.RST}")
    intel.add_argument(
        "--flag-format", "-F", type=str, default=None, metavar="FORMAT",
        help="Flag format to search for, e.g. 'HTB{}', 'FLAG{}', 'DUCTF{}'"
    )

    return p


def main() -> None:
    """Main CLI entry point for REVcon."""
    parser = _build_parser()

    # If no arguments provided, print banner + help
    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Validate target binary
    if args.binary is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if not os.path.exists(args.binary):
        print(f"{C.R}{C.B}[!]{C.RST} {C.R}Error: File '{args.binary}' does not exist.{C.RST}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.binary):
        print(f"{C.R}{C.B}[!]{C.RST} {C.R}Error: '{args.binary}' is not a file.{C.RST}", file=sys.stderr)
        sys.exit(1)

    try:
        # 1. Print banner if not in JSON mode
        if not args.json:
            print_banner()
            nc = _no_color()
            if not nc:
                print(f"{C.R}[*]{C.RST} {C.W}Analyzing binary:{C.RST} {C.B}{args.binary}{C.RST}")
                if args.quick:
                    print(f"{C.R}[*]{C.RST} {C.W}Running in{C.RST} {C.R}{C.B}QUICK{C.RST} {C.W}mode{C.RST}")
                if args.dynamic:
                    print(f"{C.R}[*]{C.RST} {C.W}Runtime analysis enabled: {C.R}{C.B}DANGEROUS EXECUTION{C.RST}")
                if args.flag_format:
                    print(f"{C.R}[*]{C.RST} {C.W}Flag format:{C.RST} {C.G}{args.flag_format}{C.RST}")
                if args.dump:
                    print(f"{C.R}[*]{C.RST} {C.W}Payload dumping enabled{C.RST}")
                if args.verbose:
                    print(f"{C.R}[*]{C.RST} {C.W}Verbose logging enabled{C.RST}\n")
            else:
                print(f"[*] Analyzing binary: {args.binary}")
                if args.quick:
                    print("[*] Running in QUICK mode")
                if args.dynamic:
                    print("[*] Runtime analysis enabled: DANGEROUS EXECUTION")
                if args.flag_format:
                    print(f"[*] Flag format: {args.flag_format}")
                if args.dump:
                    print("[*] Payload dumping enabled")
                if args.verbose:
                    print("[*] Verbose logging enabled\n")

        # 2. Run analysis
        engine = AnalysisEngine(
            args.binary,
            quick=args.quick,
            verbose=args.verbose,
            flag_format=args.flag_format,
            dynamic=args.dynamic,
            dump_payloads=args.dump
        )
        results = engine.run()

        # 3. Generate and display report
        reporter = ReportGenerator(results)
        if args.json:
            reporter.render_json()
        else:
            reporter.render_terminal()

    except KeyboardInterrupt:
        print(f"\n{C.R}{C.B}[!]{C.RST} {C.R}Analysis interrupted by user. Exiting...{C.RST}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.R}{C.B}[!]{C.RST} {C.R}Error: {str(e)}{C.RST}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
