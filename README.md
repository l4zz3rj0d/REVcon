<p align="center">
  <img src="Images/revcon.png" alt="REVcon" width="600"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-1.0.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

<h1 align="center">REVcon</h1>

<p align="center">
  Automated reconnaissance and triage framework for reverse engineering. Analyze a binary before you open a disassembler. Drop a file. Get intelligence.
</p>

---

## What It Does

REVcon performs deep static reconnaissance on ELF, PE, and Mach-O binaries and produces a structured intelligence report covering format metadata, security mitigations, language detection, symbol ranking, string categorization, import mapping, assembly-level heuristics, section entropy, and challenge type prediction. The output is a color-coded terminal dashboard or a machine-readable JSON report — ready to guide your first moves in Ghidra, IDA Pro, Binary Ninja, Cutter, or Radare2.

It runs two analysis layers: lightweight header and string parsing for fast triage, and optional Capstone-powered disassembly scanning for deeper heuristics like XOR loop detection, per-character validation, function dispatch tables, and expected input length extraction. When analysis finishes, it classifies the binary's likely challenge type and generates targeted analyst recommendations.

REVcon is not an automated solver. It does not brute force, exploit, or execute the target. It provides intelligence and guidance.

---

## Installation

### Linux / macOS

```bash
git clone https://github.com/l4zz3rj0d/REVcon.git
cd REVcon
chmod +x install.sh
./install.sh
```

### Manual

```bash
pip install .
```

---

## Usage

```
revcon <binary> [options]
```

### Scan Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--quick` | `-q` | off | Skip Capstone disassembly heuristics and entropy analysis |
| `--verbose` | `-v` | off | Show all internal debug and module logs |

### Output

| Flag | Short | Description |
|---|---|---|
| `--json` | `-j` | Output full findings as raw JSON to stdout |

### Flag Intelligence

| Flag | Short | Description |
|---|---|---|
| `--flag-format` | `-F` | Search for a flag format across strings, symbols, and base64 candidates. Example: `"FLAG{}"`, `"PREFIX{}"`, `"CUSTOM{}"` |

---

## Examples

```bash
# Standard analysis
revcon chall.bin

# Quick triage (skips disassembly and entropy)
revcon crackme -q

# JSON export for downstream tooling
revcon target.exe -j > intel.json

# Search for FLAG format
revcon challenge -F "FLAG{}"

# Search for custom CTF flag format with verbose output
revcon binary -F "PREFIX{}" -v

# Quick scan with flag search
revcon packed.bin -q -F "FLAG{}"
```

---

## Analysis Modules

### Binary Intelligence

Parses ELF, PE, and Mach-O headers. Reports format, architecture (x86, x64, ARM, ARM64, MIPS), bitness, endianness, compiler signatures (GCC, MSVC, Clang), and GNU Build ID.

### Security Analysis

Audits mitigation technologies directly from binary structure: NX, Stack Canary, RELRO (Partial/Full), PIE, Fortify Source, and ASLR compatibility. Each finding includes a beginner-friendly explanation.

### Language Detection

Matches binary signatures against Rust, Go, C++, Zig, and C compiler runtimes using a weighted indicator matrix. Reports detected language and confidence percentage.

### Symbol Intelligence

Extracts function symbols from `.symtab` and `.dynsym` sections. Demangles C++ names. Ranks symbols by reverse engineering interest (flag, check, verify, validate, decrypt, encrypt, password, secret, auth, token, main) and produces a High Value Targets list.

### String Intelligence

Extracts ASCII and UTF-16 wide strings. Categorizes into: Flag Indicators, Error Messages, Success Messages, Passwords, URLs, IP Addresses, File Paths, Registry Keys, Commands.

### Import Intelligence

Cross-references dynamic imports (strcmp, strncmp, memcmp, scanf, gets, fgets, read, write, printf, puts, rand, srand, time) against a CTF/reversing relevance database and explains each match.

### Reverse Engineering Heuristics

Uses Capstone disassembly to scan the `.text` section for:

- **Length Checks** — `cmp rsi, XX` patterns indicating expected input length
- **Per-Character Validation** — `cmp al, XX` loops checking individual bytes
- **Function Dispatch Tables** — `call qword ptr [...]` or `jmp qword ptr [...]` dynamic dispatch
- **XOR Loops** — Backward conditional jumps containing `xor reg, imm` (decryption/obfuscation)
- **Base64 Tables** — Full base64 alphabet present in string pool
- **Crypto Constants** — MD5, SHA1, SHA256 initialization vectors in code/data segments
- **Packed Binary** — UPX signatures and non-standard section names

### Entropy Analysis

Calculates Shannon entropy for each binary section. Flags sections above 7.0 as likely encrypted, compressed, or packed.

### Challenge Type Predictor

Scores all collected indicators against a weighted matrix to predict the likely challenge type: Password Check, Crackme, XOR Challenge, Crypto Challenge, Validation Challenge, Packed Binary, or License Check. Reports type and confidence percentage.

### Flag Intelligence

Activated with `-F` / `--flag-format`. Converts a format like `FLAG{}` into the regex `FLAG\{.*?\}` and searches strings, symbols, and decoded base64 candidates. Reports direct matches, partial fragment matches (prefix, `flag`, `secret`, `token`), and an overall confidence level (HIGH / MEDIUM / LOW).

### Recommendation Engine

Synthesizes all findings into a targeted analyst summary: detected language, predicted challenge type, expected input length, primary target functions, analysis strategies tailored to the compiler/runtime, and a concrete recommended next step.

---

## Plugin System

REVcon dynamically loads any Python module placed in `revcon/plugins/` that inherits from `BasePlugin`. Two plugins ship by default:

- **XOR Detector** — Searches for XOR decryption loop markers and keywords.
- **Crypto Detector** — Searches for cryptographic constants, imports, and library API calls.

### Writing a Plugin

```python
from typing import Dict, Any
from revcon.plugins.base import BasePlugin

class CustomDetector(BasePlugin):
    @property
    def name(self) -> str:
        return "Custom Detector"

    @property
    def description(self) -> str:
        return "Scans for custom indicators."

    def run(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        # Access metadata["strings"], metadata["symbols"], etc.
        return {"detected": len(findings) > 0, "findings": findings}
```

---

## Output Formats

- **Terminal** — Color-coded dashboard with section frames, inline explanations, and analyst summary.
- **JSON** — Full-fidelity structured report with all metadata, categories, and plugin findings. Pipe directly into downstream tooling.

---

## Requirements

- Python 3.11+
- `colorama`, `capstone`, `pyelftools`, `pefile`, `macholib`

---

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for Version 1.0, 2.0, and 3.0 plans.

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/new-detector`.
3. Write modular, typed Python with docstrings.
4. Verify output with `python3 revcon.py <target>`.
5. Submit a Pull Request.

---

For authorized security research and education only.

---

## Author

<a href="https://l4zz3rj0d.github.io">
  <img src="https://img.shields.io/badge/Author-L4ZZ3RJ0D-c0392b?style=for-the-badge" alt="L4ZZ3RJ0D"/>
</a>