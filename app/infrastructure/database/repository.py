from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.interfaces.scan_repository import ScanRepository
from app.domain.inventory.stored_scan import StoredScanReport
from app.domain.sbom.models import SBOMComponent, SBOMDocument, SBOMFormat
from app.infrastructure.database.models import (
    ComponentRecord,
    FirmwareRecord,
    SBOMRecord,
    ScanRecord,
    VulnerabilityRecord,
)


class SQLAlchemyScanRepository(ScanRepository):
    """Persist and load scan reports from SQLite via SQLAlchemy."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save_scan(
        self,
        extraction_result: ExtractionResult,
        scan_result: ScanResult,
        firmware_metadata: FirmwareMetadata | None,
        sboms: list[SBOMDocument],
    ) -> int:
        with self._session_factory() as session:
            firmware = FirmwareRecord(
                filename=Path(extraction_result.firmware_path).name,
                architecture=extraction_result.architecture,
                filesystem_type=extraction_result.filesystem_type,
                extracted_path=str(extraction_result.extracted_path),
                kernel_information=(
                    firmware_metadata.kernel_information if firmware_metadata is not None else None
                ),
                vendor_information=(
                    firmware_metadata.vendor_information if firmware_metadata is not None else None
                ),
            )
            session.add(firmware)
            session.flush()

            scan = ScanRecord(firmware_id=firmware.id, risk_score=scan_result.risk_score)
            session.add(scan)
            session.flush()

            for component in scan_result.components:
                session.add(
                    ComponentRecord(
                        scan_id=scan.id,
                        name=component.name,
                        version=component.version,
                        confidence=component.confidence,
                        evidence=self._serialize_evidence(component.evidence),
                    )
                )

            for vulnerability in scan_result.vulnerabilities:
                session.add(
                    VulnerabilityRecord(
                        scan_id=scan.id,
                        cve_id=vulnerability.cve_id,
                        severity=vulnerability.severity,
                        description=vulnerability.description,
                        component_name=vulnerability.component_name,
                        component_version=vulnerability.component_version,
                        confidence=vulnerability.confidence,
                        evidence=self._serialize_evidence(vulnerability.evidence),
                    )
                )

            for sbom in sboms:
                session.add(
                    SBOMRecord(
                        scan_id=scan.id,
                        format=sbom.format.value,
                        payload=json.dumps(sbom.content),
                    )
                )

            session.commit()
            return scan.id

    def get_report(self, report_id: int) -> StoredScanReport | None:
        with self._session_factory() as session:
            scan = session.scalar(select(ScanRecord).where(ScanRecord.id == report_id))
            if scan is None:
                return None

            components = tuple(
                Component(
                    name=row.name,
                    version=row.version,
                    confidence=row.confidence,
                    evidence=self._deserialize_evidence(row.evidence),
                )
                for row in session.scalars(
                    select(ComponentRecord).where(ComponentRecord.scan_id == scan.id)
                )
            )
            vulnerabilities = tuple(
                Vulnerability(
                    cve_id=row.cve_id,
                    severity=row.severity,
                    description=row.description,
                    component_name=row.component_name,
                    component_version=row.component_version,
                    confidence=row.confidence,
                    evidence=self._deserialize_evidence(row.evidence),
                )
                for row in session.scalars(
                    select(VulnerabilityRecord).where(VulnerabilityRecord.scan_id == scan.id)
                )
            )
            sboms = tuple(
                self._deserialize_sbom(row)
                for row in session.scalars(select(SBOMRecord).where(SBOMRecord.scan_id == scan.id))
            )

            firmware = session.scalar(
                select(FirmwareRecord).where(FirmwareRecord.id == scan.firmware_id)
            )
            firmware_metadata = None
            if firmware is not None and (
                firmware.kernel_information is not None or firmware.vendor_information is not None
            ):
                firmware_metadata = FirmwareMetadata(
                    architecture=firmware.architecture,
                    filesystem_type=firmware.filesystem_type,
                    kernel_information=firmware.kernel_information or "Unknown",
                    vendor_information=firmware.vendor_information or "Unknown",
                )

            return StoredScanReport(
                report_id=scan.id,
                risk_score=scan.risk_score,
                components=components,
                vulnerabilities=vulnerabilities,
                sboms=sboms,
                firmware_metadata=firmware_metadata,
            )

    def _deserialize_sbom(self, sbom_record: SBOMRecord) -> SBOMDocument:
        payload = json.loads(sbom_record.payload)
        if sbom_record.format == SBOMFormat.CYCLONEDX_JSON.value:
            components = tuple(
                SBOMComponent(
                    name=component.get("name", "unknown"),
                    version=component.get("version", "unknown"),
                )
                for component in payload.get("components", [])
            )
            format = SBOMFormat.CYCLONEDX_JSON
        else:
            components = tuple(
                SBOMComponent(
                    name=package.get("name", "unknown"),
                    version=package.get("versionInfo", "unknown"),
                )
                for package in payload.get("packages", [])
            )
            format = SBOMFormat.SPDX_JSON

        return SBOMDocument(format=format, components=components, content=payload)

    @staticmethod
    def _serialize_evidence(evidence: tuple[Evidence, ...]) -> str:
        return json.dumps(
            [{"source": item.source, "path": item.path, "detail": item.detail} for item in evidence]
        )

    @staticmethod
    def _deserialize_evidence(payload: str) -> tuple[Evidence, ...]:
        try:
            values = json.loads(payload)
        except json.JSONDecodeError:
            return ()
        return tuple(Evidence(value["source"], value["path"], value["detail"]) for value in values)
