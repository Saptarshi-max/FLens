from pathlib import Path
from typing import Protocol

from app.domain.entities.extraction_result import ExtractionResult


class FirmwareExtractor(Protocol):
    """Extract a filesystem from a firmware image path."""

    def extract(self, firmware_path: Path) -> ExtractionResult:
        """Extract firmware and return extraction metadata."""
