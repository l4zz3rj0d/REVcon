import math
from typing import Dict, List, Any
from elftools.elf.elffile import ELFFile
import pefile

class EntropyAnalysis:
    """Calculates Shannon entropy of sections to identify encrypted, packed, or compressed regions."""

    def __init__(self, filepath: str, binary_format: str):
        self.filepath = filepath
        self.format = binary_format

    def analyze(self) -> Dict[str, Any]:
        """Calculates section entropies."""
        sections = []

        if self.format == "ELF":
            sections = self._analyze_elf()
        elif self.format == "PE":
            sections = self._analyze_pe()
        else:
            sections = self._analyze_raw()

        # Find high entropy sections
        high_entropy_sections = []
        for sec in sections:
            if sec["entropy"] > 7.0:
                high_entropy_sections.append(sec)

        return {
            "sections": sections,
            "high_entropy_sections": high_entropy_sections,
            "has_high_entropy": len(high_entropy_sections) > 0
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy of a byte array."""
        if not data:
            return 0.0
        
        # Calculate frequency of each byte
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
            
        entropy = 0.0
        total_len = len(data)
        for count in counts:
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
                
        return round(entropy, 4)

    def _analyze_elf(self) -> List[Dict[str, Any]]:
        """Calculates entropy of ELF sections."""
        results = []
        try:
            with open(self.filepath, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    # Skip empty sections
                    if section['sh_size'] > 0:
                        try:
                            data = section.data()
                            ent = self._calculate_entropy(data)
                            results.append({
                                "name": section.name if section.name else f"Index {section.header.sh_name}",
                                "size": section['sh_size'],
                                "entropy": ent,
                                "status": self._entropy_status(ent)
                            })
                        except Exception:
                            pass
        except Exception:
            pass
        return results

    def _analyze_pe(self) -> List[Dict[str, Any]]:
        """Calculates entropy of PE sections."""
        results = []
        try:
            pe = pefile.PE(self.filepath)
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                data = section.get_data()
                if data:
                    ent = self._calculate_entropy(data)
                    results.append({
                        "name": name,
                        "size": len(data),
                        "entropy": ent,
                        "status": self._entropy_status(ent)
                    })
            pe.close()
        except Exception:
            pass
        return results

    def _analyze_raw(self) -> List[Dict[str, Any]]:
        """Fallback: calculates entropy of the entire binary file as a single section."""
        results = []
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
                if data:
                    ent = self._calculate_entropy(data)
                    results.append({
                        "name": "RAW_BINARY",
                        "size": len(data),
                        "entropy": ent,
                        "status": self._entropy_status(ent)
                    })
        except Exception:
            pass
        return results

    def _entropy_status(self, entropy: float) -> str:
        """Determines category status of entropy values."""
        if entropy > 7.2:
            return "Highly Encrypted / Compressed / Packed"
        elif entropy > 6.0:
            return "Slightly Encructured / Obfuscated Code"
        else:
            return "Standard Code / Data"
