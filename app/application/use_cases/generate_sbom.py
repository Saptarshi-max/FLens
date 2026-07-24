from dataclasses import dataclass

from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.sbom_generator import SBOMGenerator
from app.domain.sbom.models import SBOMDocument, SBOMFormat


@dataclass(frozen=True, slots=True)
class GenerateSBOMResult:
    """Generated SBOM variants for a scan."""

    cyclonedx: SBOMDocument
    spdx: SBOMDocument


class GenerateSBOMUseCase:
    """Generate CycloneDX and SPDX SBOM documents."""

    def __init__(self, sbom_generator: SBOMGenerator) -> None:
        self._sbom_generator = sbom_generator

    def execute(self, scan_result: ScanResult) -> GenerateSBOMResult:
        cyclonedx = self._sbom_generator.generate(scan_result, SBOMFormat.CYCLONEDX_JSON)
        spdx = self._sbom_generator.generate(scan_result, SBOMFormat.SPDX_JSON)
        return GenerateSBOMResult(cyclonedx=cyclonedx, spdx=spdx)
