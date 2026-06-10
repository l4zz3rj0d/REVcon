"""
REVcon: Automated Reconnaissance and Triage Framework for Reverse Engineering
Author: Lazzer
"""

import argparse
import sys
import os
from colorama import init

from revcon.banner import print_banner
from revcon.engine import AnalysisEngine
from revcon.report import ReportGenerator

def main() -> None:
    """Main CLI entry point for REVcon."""
    # Initialize colorama for cross-platform color support
    init(autoreset=True)

    parser = argparse.ArgumentParser(
        description="REVcon - Reverse Engineering Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "binary",
        help="Path to the binary file to analyze"
    )
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Run quick checks only (skip heavy disasm heuristics and entropy analysis)"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output findings in raw JSON format to stdout"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging/debug output"
    )
    parser.add_argument(
        "-F", "--flag-format",
        type=str,
        default=None,
        metavar="FORMAT",
        help="Flag format to search for, e.g. 'HTB{}', 'FLAG{}', 'DUCTF{}'"
    )

    # If no arguments provided, print help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Validate target binary path
    if not os.path.exists(args.binary):
        print(f"[-] Error: File '{args.binary}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isfile(args.binary):
        print(f"[-] Error: '{args.binary}' is not a file.", file=sys.stderr)
        sys.exit(1)

    try:
        # 1. Print banner if not in JSON mode
        if not args.json:
            print_banner()
            print(f"[*] Analyzing binary: {args.binary}")
            if args.quick:
                print("[*] Running in QUICK mode")
            if args.flag_format:
                print(f"[*] Flag format: {args.flag_format}")
            if args.verbose:
                print("[*] Verbose logging enabled\n")

        # 2. Run analysis
        engine = AnalysisEngine(
            args.binary,
            quick=args.quick,
            verbose=args.verbose,
            flag_format=args.flag_format
        )
        results = engine.run()

        # 3. Generate and display report
        reporter = ReportGenerator(results)
        if args.json:
            reporter.render_json()
        else:
            reporter.render_terminal()

    except KeyboardInterrupt:
        print("\n[-] Analysis interrupted by user. Exiting...", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
