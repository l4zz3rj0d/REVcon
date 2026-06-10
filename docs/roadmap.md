# REVcon Development Roadmap

This document outlines the version history and future roadmap for the **REVcon** reverse engineering reconnaissance framework.

---

## 📌 Version 1.0.0 (Current Release)
The complete redesign of the framework from basic subprocess wrapper checks into a professional, modular static reconnaissance engine.
- **Binary Intelligence**: Complete ELF, PE, and Mach-O format header parsers including arch, bitness, endianness, compiler, and build metadata.
- **Advanced Heuristics**: Capstone-based static assembly scanner detecting expected input length checks, character-by-character validation, function pointers/dispatch tables, and xor decrypt loops.
- **Shannon Entropy Analysis**: Measures section-level randomness to find packed, compressed, or encrypted code/data segments.
- **Dynamic Plugin System**: Base plugin loader allowing community developers to extend detection strategies at runtime (with built-in `XOR Detector` and `Crypto Detector` modules).
- **Import & Symbol Ranking**: Auto-demangles C++ symbols, scores high-value functions, and flags key imports with novice-friendly explanations.
- **Language Detection**: Confidently categorizes Rust, Go, C++, Zig, and C binaries with weighted signature matching.

---

## 🚀 Version 2.0.0 (Upcoming)
Focuses on disassembler integration and interactive workflow tooling.
- **Ghidra/IDA Pro Scripts**: Generate annotations, bookmarks, and comments based on REVcon analysis to auto-initialize and label projects.
- **FLOSS-like Stack String Recovery**: Implement dynamic emulation or backtracking to extract strings constructed dynamically at runtime in stack buffers.
- **Binary Diffing Helper**: Add support for diffing two versions of the same crackme or patch to isolate modified validation paths.
- **Advanced PE/Mach-O Parsing**: Support fat universal Mach-O binaries and extract rich signature/header attributes from PE resources.

---

## 🔮 Version 3.0.0 (Future Vision)
Introduces lightweight dynamic tracing and symbolic execution helpers.
- **Qemu/Unicorn Emulation Triage**: Auto-emulate execution up to target validator functions or inputs to track dynamic branching.
- **Symbolic Input Solver Integration**: Integrate with Angr for lightweight constraint solving on simple crackmes directly from CLI.
- **Dynamic Taint Analysis**: Log data flow from standard input read buffers directly to comparator instructions.
