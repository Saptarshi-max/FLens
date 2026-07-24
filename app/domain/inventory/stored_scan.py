from dataclasses import dataclass

from app.domain.entities.component import Component
from app.domain.entities.vulnerability import Vulnerability
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.sbom.models import SBOMDocument


@dataclass(frozen=True, slots=True)
class StoredScanReport:
    """A persisted firmware scan report returned from storage."""

    report_id: int
    risk_score: str
    components: tuple[Component, ...]
    vulnerabilities: tuple[Vulnerability, ...]
    sboms: tuple[SBOMDocument, ...]
    firmware_metadata: FirmwareMetadata | None
