from dataclasses import dataclass
from pathlib import Path

from app.application.use_cases.analyze_firmware import (
    AnalyzeFirmwareUseCase,
    FirmwareAnalysisResult,
)
from app.application.use_cases.generate_sbom import GenerateSBOMResult, GenerateSBOMUseCase
from app.application.use_cases.store_scan import StoreScanUseCase


@dataclass(frozen=True, slots=True)
class FirmwareIntelligenceResult:
    """Full intelligence result containing analysis, SBOM, and persisted report id."""

    analysis: FirmwareAnalysisResult
    sboms: GenerateSBOMResult
    report_id: int


class AnalyzeFirmwareIntelligenceUseCase:
    """Run extraction, scanning, SBOM generation, and persistence."""

    def __init__(
        self,
        analyze_firmware_use_case: AnalyzeFirmwareUseCase,
        generate_sbom_use_case: GenerateSBOMUseCase,
        store_scan_use_case: StoreScanUseCase,
    ) -> None:
        self._analyze_firmware_use_case = analyze_firmware_use_case
        self._generate_sbom_use_case = generate_sbom_use_case
        self._store_scan_use_case = store_scan_use_case

    def execute(self, firmware_path: Path) -> FirmwareIntelligenceResult:
        analysis = self._analyze_firmware_use_case.execute(firmware_path)
        sboms = self._generate_sbom_use_case.execute(analysis.scan_result)
        report_id = self._store_scan_use_case.execute(
            extraction_result=analysis.extraction_result,
            scan_result=analysis.scan_result,
            firmware_metadata=analysis.firmware_metadata,
            sboms=[sboms.cyclonedx, sboms.spdx],
        )
        return FirmwareIntelligenceResult(analysis=analysis, sboms=sboms, report_id=report_id)
