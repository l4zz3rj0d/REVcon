import os
from typing import Dict, Any, Optional
from elftools.elf.elffile import ELFFile
import pefile
from macholib.MachO import MachO

class BinaryIntelligence:
    """Detects format, architecture, bitness, endianness, compiler, and build information."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.size = os.path.getsize(filepath)

    def analyze(self) -> Dict[str, Any]:
        """Runs binary intelligence extraction."""
        result = {
            "format": "Unknown",
            "arch": "Unknown",
            "bitness": "Unknown",
            "endianness": "Unknown",
            "compiler": "Unknown",
            "build_info": "Unknown",
            "file_size": self.size
        }

        # Read magic bytes
        try:
            with open(self.filepath, "rb") as f:
                magic = f.read(4)
        except Exception as e:
            result["build_info"] = f"Error reading file: {str(e)}"
            return result

        if magic.startswith(b"\x7fELF"):
            self._analyze_elf(result)
        elif magic.startswith(b"MZ"):
            self._analyze_pe(result)
        elif magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            self._analyze_macho(result)
        else:
            # Fallback based on file extensions or raw bytes
            result["format"] = "Raw / Unknown Binary"
            result["endianness"] = "Unknown"

        return result

    def _analyze_elf(self, result: Dict[str, Any]) -> None:
        """Parses ELF files using pyelftools."""
        result["format"] = "ELF"
        try:
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                
                # Bitness
                result["bitness"] = f"{elf.elfclass}-bit"
                
                # Endianness
                result["endianness"] = "Little Endian" if elf.little_endian else "Big Endian"
                
                # Architecture
                machine = elf.header["e_machine"]
                if "EM_X86_64" in machine or machine == 62:
                    result["arch"] = "x64"
                elif "EM_386" in machine or machine == 3:
                    result["arch"] = "x86"
                elif "EM_AARCH64" in machine or machine == 183:
                    result["arch"] = "ARM64"
                elif "EM_ARM" in machine or machine == 40:
                    result["arch"] = "ARM"
                elif "EM_MIPS" in machine or machine == 8:
                    result["arch"] = "MIPS"
                else:
                    result["arch"] = str(machine)

                # Compiler clues from .comment section
                comments = []
                comment_sec = elf.get_section_by_name(".comment")
                if comment_sec:
                    data = comment_sec.data()
                    # Split comments by null bytes
                    parts = data.split(b"\x00")
                    for p in parts:
                        cleaned = p.decode("utf-8", errors="ignore").strip()
                        if cleaned:
                            comments.append(cleaned)
                
                if comments:
                    result["compiler"] = ", ".join(comments)
                
                # Build information / Build ID
                build_id_sec = elf.get_section_by_name(".note.gnu.build-id")
                if build_id_sec:
                    from elftools.elf.sections import NoteSection
                    if isinstance(build_id_sec, NoteSection):
                        notes = list(build_id_sec.iter_notes())
                        if notes:
                            desc = notes[0]['n_desc']
                            build_id = desc.hex() if isinstance(desc, bytes) else str(desc)
                            result["build_info"] = f"GNU Build ID: {build_id}"

        except Exception as e:
            result["build_info"] = f"Error parsing ELF: {str(e)}"

    def _analyze_pe(self, result: Dict[str, Any]) -> None:
        """Parses PE files using pefile."""
        result["format"] = "PE"
        result["endianness"] = "Little Endian" # PE is always Little Endian
        try:
            pe = pefile.PE(self.filepath)
            
            # Architecture / Machine
            machine = pe.FILE_HEADER.Machine
            if machine == 0x8664:
                result["arch"] = "x64"
                result["bitness"] = "64-bit"
            elif machine == 0x014c:
                result["arch"] = "x86"
                result["bitness"] = "32-bit"
            elif machine == 0xaa64:
                result["arch"] = "ARM64"
                result["bitness"] = "64-bit"
            elif machine == 0x01c0 or machine == 0x01c4:
                result["arch"] = "ARM"
                result["bitness"] = "32-bit"
            elif machine == 0x0266:
                result["arch"] = "MIPS"
                result["bitness"] = "32-bit"
            else:
                result["arch"] = f"Unknown ({hex(machine)})"
            
            # Compiler clues & Build Info
            # Scan sections and headers
            clues = []
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                for entry in pe.DIRECTORY_ENTRY_DEBUG:
                    if hasattr(entry.struct, "Type") and entry.struct.Type == 2: # CodeView
                        clues.append("CodeView Debug Info Present")
            
            # Check for Rich Header (MSVC compiler signature)
            if pe.RICH_HEADER:
                clues.append("MSVC Rich Header Present")
                result["compiler"] = "Microsoft Visual C++ (MSVC)"

            if not result["compiler"] or result["compiler"] == "Unknown":
                # Check section names
                section_names = [s.Name.decode("utf-8", errors="ignore").strip("\x00") for s in pe.sections]
                if ".rdata" in section_names:
                    clues.append("Standard PE Section Layout")

            result["build_info"] = " | ".join(clues) if clues else "None"
            pe.close()

        except Exception as e:
            result["build_info"] = f"Error parsing PE: {str(e)}"

    def _analyze_macho(self, result: Dict[str, Any]) -> None:
        """Parses Mach-O files using macholib."""
        result["format"] = "Mach-O"
        try:
            m = MachO(self.filepath)
            # macholib processes headers
            if m.headers:
                header = m.headers[0]
                
                # Bitness and Endianness
                magic = header.header.magic
                if magic == 0xfeedfacf: # MH_MAGIC_64
                    result["bitness"] = "64-bit"
                    result["endianness"] = "Little Endian"
                elif magic == 0xcffaedfe: # MH_CIGAM_64
                    result["bitness"] = "64-bit"
                    result["endianness"] = "Big Endian"
                elif magic == 0xfeedface: # MH_MAGIC
                    result["bitness"] = "32-bit"
                    result["endianness"] = "Little Endian"
                elif magic == 0xcefaedfe: # MH_CIGAM
                    result["bitness"] = "32-bit"
                    result["endianness"] = "Big Endian"

                # Architecture (CPU type)
                cputype = header.header.cputype
                if cputype == 0x01000007 or cputype == 7: # CPU_TYPE_X86_64 / CPU_TYPE_I386
                    result["arch"] = "x64" if result["bitness"] == "64-bit" else "x86"
                elif cputype == 0x0100000c or cputype == 12: # CPU_TYPE_ARM64 / CPU_TYPE_ARM
                    result["arch"] = "ARM64" if result["bitness"] == "64-bit" else "ARM"
                else:
                    result["arch"] = f"CPU Type {cputype}"

                result["compiler"] = "Clang / Xcode"
                result["build_info"] = "Apple Mach-O executable"
        except Exception as e:
            result["build_info"] = f"Error parsing Mach-O: {str(e)}"
