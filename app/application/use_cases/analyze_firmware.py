from dataclasses import dataclass
from pathlib import Path

from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.firmware_extractor import FirmwareExtractor


@dataclass(frozen=True, slots=True)
class FirmwareAnalysisResult:
    """Combined result of extraction and security scan."""

    extraction_result: ExtractionResult
    scan_result: ScanResult


class AnalyzeFirmwareUseCase:
    """Extract firmware, then analyze the extracted filesystem."""

    def __init__(
        self,
        firmware_extractor: FirmwareExtractor,
        scan_use_case: ScanFirmwareUseCase,
    ) -> None:
        self._firmware_extractor = firmware_extractor
        self._scan_use_case = scan_use_case

    def execute(self, firmware_path: Path) -> FirmwareAnalysisResult:
        extraction = self._firmware_extractor.extract(firmware_path)
        scan_result = self._scan_use_case.execute(extraction.extracted_path)
        return FirmwareAnalysisResult(extraction_result=extraction, scan_result=scan_result)
