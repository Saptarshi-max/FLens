from pathlib import Path

from app.domain.entities.extraction_result import ExtractionResult
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.interfaces.firmware_metadata_extractor import FirmwareMetadataExtractor


class RootfsFirmwareMetadataExtractor(FirmwareMetadataExtractor):
    """Extract firmware metadata from extraction details and rootfs files."""

    def extract(self, extraction_result: ExtractionResult, rootfs_path: Path) -> FirmwareMetadata:
        kernel_information = self._detect_kernel(rootfs_path)
        vendor_information = self._detect_vendor(rootfs_path)
        return FirmwareMetadata(
            architecture=extraction_result.architecture,
            filesystem_type=extraction_result.filesystem_type,
            kernel_information=kernel_information,
            vendor_information=vendor_information,
        )

    def _detect_kernel(self, rootfs_path: Path) -> str:
        candidates = ["vmlinuz", "zImage", "uImage", "bzImage"]
        for candidate in candidates:
            matches = list(rootfs_path.rglob(candidate))
            if matches:
                return candidate
        return "Unknown"

    def _detect_vendor(self, rootfs_path: Path) -> str:
        vendor_files = [rootfs_path / "etc" / "os-release", rootfs_path / "etc" / "banner"]
        for vendor_file in vendor_files:
            if not vendor_file.exists() or not vendor_file.is_file():
                continue
            content = vendor_file.read_text(encoding="utf-8", errors="ignore").lower()
            for vendor in ["tp-link", "d-link", "netgear", "linksys"]:
                if vendor in content:
                    return vendor
        return "Unknown"
