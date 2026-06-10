<p align="center">
  <img src="Images/revcon.png" alt="REVcon" width="600"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-1.2.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

<h1 align="center">REVcon</h1>

<p align="center">
  Automated reconnaissance, triage, and intelligence framework for reverse engineering. Analyze a binary before you open a disassembler. Drop a file. Get intelligence.
</p>

---

## What It Does

REVcon performs deep static and dynamic reconnaissance on ELF, PE, and Mach-O binaries and shared libraries. It constructs a structured, color-coded intelligence report grouped into 11 distinct attack surfaces designed to guide your first moves in a disassembler (Ghidra, IDA Pro, Binary Ninja, Cutter). 

Instead of dumping raw metadata, REVcon behaves as a reverse-engineering assistant by ranking internal functions, tracing relationship structures, reconstructing obfuscated constants, resolving environment variables, and flagging dynamic payload loaders.

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
| `--verbose` | `-v` | off | Show all internal logs and display hidden compiler boilerplate symbols |
| `--json` | `-j` | off | Output full findings as raw JSON to stdout |
| `--flag-format` | `-F` | None | Search for a flag format across strings, symbols, and base64 candidates. Example: `"FLAG{}"` |

---

## Examples

```bash
# Standard static reconnaissance
revcon chall.bin

# Run with dynamic analysis tracer (DANGEROUS EXECUTION)
revcon chall.bin -D

# Export JSON report for external parsers
revcon target.exe -j > intel.json

# Scan for custom flag formats
revcon challenge -F "FLAG{}"
```

---

## Analysis Modules & Features

### 1. Dynamic Function Discovery & Noise Filtering
Crawl symbol tables, dynamic symbols, PLT/imports, and discovered call targets recursively to map all internal subroutines. Automatically filters out compiler-generated boilerplate noise (e.g. `_start`, `frame_dummy`, `_init`, `_fini`) by default to keep the focus purely on user-defined code.

### 2. Interesting Function Scoring & Ranking
Scores functions based on logic complexity and high-interest API calls. Ranks subroutines dynamically to surface target validation loops, crypto, dynamic loaders, and debugger bypass points. Score metrics:
- **mmap/mprotect/VirtualAlloc**: +45
- **ptrace/anti-debug**: +45
- **crypt/decrypt/aes/rc4**: +40
- **dlopen/dlsym**: +35
- **getenv**: +30
- **strcmp/memcmp**: +25

### 3. Environment Variable Backtracking
Static argument backtracking scans registers and offset parameters preceding `getenv` calls to extract required environment variable names (e.g. `SAT_PROD_ENVIRONMENT`). Extracted names are automatically exported to the runtime execution environment.

### 4. Runtime Payload Analysis Engine
Traces dynamic memory mappings and permissions. Highlights execution blocks allocating `PROT_EXEC` (7) space or invoking writes into executable segments (suspicious self-modifying code or unpacked runtime payloads).

### 5. Library Intelligence & Relationship Surface
Provides deep triage for library files (`.so`, `.dll`, `.dylib`), exposing non-boilerplate exports, suspicious exports, and likely entry points. A visual relationship tree diagrams import/export linkages.

### 6. Visually Filtered Call Graph
Traces function dependency trees starting from `main` or custom library export targets, hiding boilerplate code execution paths.

### 7. Suspicious Constant Recovery
Reconstructs stack-constructed strings and single-byte cipher arrays (XOR/ADD/SUB). Utilizes heuristic entropy and repetition filtering to drop padding-based false positives.

### 8. Analyst Mode ("Why This Matters")
Presents professional reverse-engineering guidance under each surface to detail the threat significance of findings and guide analysts to their next debug actions.

---

## Requirements

- Python 3.11+
- `colorama`, `capstone`, `pyelftools`, `pefile`, `macholib`

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