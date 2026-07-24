from pathlib import Path
from typing import Protocol

from app.domain.entities.extraction_result import ExtractionResult
from app.domain.firmware.metadata import FirmwareMetadata


class FirmwareMetadataExtractor(Protocol):
    """Extract structured firmware metadata from extracted rootfs."""

    def extract(self, extraction_result: ExtractionResult, rootfs_path: Path) -> FirmwareMetadata:
        """Return normalized firmware metadata."""
