from typing import Protocol

from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.inventory.stored_scan import StoredScanReport
from app.domain.sbom.models import SBOMDocument


class ScanRepository(Protocol):
    """Persistence contract for scan outputs and reports."""

    def save_scan(
        self,
        extraction_result: ExtractionResult,
        scan_result: ScanResult,
        firmware_metadata: FirmwareMetadata | None,
        sboms: list[SBOMDocument],
    ) -> int:
        """Persist scan data and return report identifier."""

    def get_report(self, report_id: int) -> StoredScanReport | None:
        """Retrieve a persisted report by identifier."""
