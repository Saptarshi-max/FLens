from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.interfaces.scan_repository import ScanRepository
from app.domain.sbom.models import SBOMDocument


class StoreScanUseCase:
    """Persist scan results and related artifacts."""

    def __init__(self, scan_repository: ScanRepository) -> None:
        self._scan_repository = scan_repository

    def execute(
        self,
        extraction_result: ExtractionResult,
        scan_result: ScanResult,
        firmware_metadata: FirmwareMetadata | None,
        sboms: list[SBOMDocument],
    ) -> int:
        return self._scan_repository.save_scan(
            extraction_result=extraction_result,
            scan_result=scan_result,
            firmware_metadata=firmware_metadata,
            sboms=sboms,
        )
