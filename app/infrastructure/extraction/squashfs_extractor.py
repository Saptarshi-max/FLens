from pathlib import Path

from app.domain.entities.extraction_result import ExtractionResult
from app.domain.interfaces.firmware_extractor import FirmwareExtractor
from app.infrastructure.extraction.errors import ExtractionError


class SquashfsExtractor(FirmwareExtractor):
    """Placeholder for a dedicated SquashFS extraction backend."""

    def extract(self, firmware_path: Path) -> ExtractionResult:
        raise ExtractionError(
            "SquashFS extractor backend is not implemented yet. Use BinwalkExtractor for Phase 2."
        )
