from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePlugin(ABC):
    """Abstract Base Class that all REVcon plugins must inherit from."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the unique name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Returns a brief description of what the plugin detects."""
        pass

    @abstractmethod
    def run(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the plugin analysis.
        
        Args:
            metadata: A dictionary containing the full extracted binary metadata
                      (includes binary_intel, security, language, symbols, strings, imports, heuristics, entropy).

        Returns:
            A dictionary containing the analysis findings/detections.
        """
        pass
