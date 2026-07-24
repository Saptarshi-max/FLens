from typing import Protocol

from app.domain.entities.scan_result import ScanResult
from app.domain.sbom.models import SBOMDocument, SBOMFormat


class SBOMGenerator(Protocol):
    """Generate SBOM documents from scan results."""

    def generate(self, scan_result: ScanResult, format: SBOMFormat) -> SBOMDocument:
        """Generate an SBOM in the target format."""
