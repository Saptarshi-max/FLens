from pathlib import Path

from app.domain.entities.component import Component
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.sbom.models import SBOMComponent, SBOMDocument, SBOMFormat
from app.infrastructure.database.engine import create_database_engine, create_session_factory
from app.infrastructure.database.repository import SQLAlchemyScanRepository


def test_save_and_get_report(tmp_path: Path) -> None:
    db_path = tmp_path / "flens_test.db"
    engine = create_database_engine(db_path)
    repository = SQLAlchemyScanRepository(create_session_factory(engine))

    extraction = ExtractionResult(
        firmware_path=tmp_path / "router.bin",
        extracted_path=tmp_path / "rootfs",
        filesystem_type="SquashFS",
        architecture="ARM",
        metadata={"backend": "test"},
    )
    scan_result = ScanResult(
        components=(Component(name="openssl", version="1.1.1d"),),
        vulnerabilities=(
            Vulnerability(
                cve_id="CVE-2022-0778",
                severity="HIGH",
                description="Test CVE",
            ),
        ),
        risk_score="HIGH",
    )
    metadata = FirmwareMetadata(
        architecture="ARM",
        filesystem_type="SquashFS",
        kernel_information="uImage",
        vendor_information="tp-link",
    )
    sboms = [
        SBOMDocument(
            format=SBOMFormat.CYCLONEDX_JSON,
            components=(SBOMComponent(name="openssl", version="1.1.1d"),),
            content={"bomFormat": "CycloneDX", "components": [{"name": "openssl"}]},
        ),
        SBOMDocument(
            format=SBOMFormat.SPDX_JSON,
            components=(SBOMComponent(name="openssl", version="1.1.1d"),),
            content={"spdxVersion": "SPDX-2.3", "packages": [{"name": "openssl"}]},
        ),
    ]

    report_id = repository.save_scan(extraction, scan_result, metadata, sboms)
    report = repository.get_report(report_id)

    assert report is not None
    assert report.report_id == report_id
    assert report.risk_score == "HIGH"
    assert len(report.components) == 1
    assert len(report.vulnerabilities) == 1
    assert len(report.sboms) == 2
    assert report.firmware_metadata is not None
    assert report.firmware_metadata.vendor_information == "tp-link"
