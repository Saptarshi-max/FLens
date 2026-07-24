from dataclasses import dataclass
from pathlib import Path

from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.interfaces.firmware_extractor import FirmwareExtractor
from app.domain.interfaces.firmware_metadata_extractor import FirmwareMetadataExtractor


@dataclass(frozen=True, slots=True)
class FirmwareAnalysisResult:
    """Combined result of extraction and security scan."""

    extraction_result: ExtractionResult
    scan_result: ScanResult
    firmware_metadata: FirmwareMetadata | None = None


class AnalyzeFirmwareUseCase:
    """Extract firmware, then analyze the extracted filesystem."""

    def __init__(
        self,
        firmware_extractor: FirmwareExtractor,
        scan_use_case: ScanFirmwareUseCase,
        firmware_metadata_extractor: FirmwareMetadataExtractor | None = None,
    ) -> None:
        self._firmware_extractor = firmware_extractor
        self._scan_use_case = scan_use_case
        self._firmware_metadata_extractor = firmware_metadata_extractor

    def execute(self, firmware_path: Path) -> FirmwareAnalysisResult:
        extraction = self._firmware_extractor.extract(firmware_path)
        scan_result = self._scan_use_case.execute(extraction.extracted_path)
        firmware_metadata = None
        if self._firmware_metadata_extractor is not None:
            firmware_metadata = self._firmware_metadata_extractor.extract(
                extraction,
                extraction.extracted_path,
            )

        return FirmwareAnalysisResult(
            extraction_result=extraction,
            scan_result=scan_result,
            firmware_metadata=firmware_metadata,
        )
