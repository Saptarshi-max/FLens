from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.application.use_cases.analyze_firmware import FirmwareAnalysisResult
from app.application.use_cases.analyze_firmware_intelligence import FirmwareIntelligenceResult
from app.application.use_cases.generate_sbom import GenerateSBOMResult
from app.config.container import Container
from app.domain.entities.component import Component
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.domain.firmware.metadata import FirmwareMetadata
from app.domain.inventory.stored_scan import StoredScanReport
from app.domain.sbom.models import SBOMComponent, SBOMDocument, SBOMFormat
from app.presentation.api.main import api

client = TestClient(api)


class _FakeRepository:
    def get_report(self, report_id: int) -> StoredScanReport | None:
        if report_id != 7:
            return None
        return StoredScanReport(
            report_id=7,
            risk_score="HIGH",
            components=(Component(name="openssl", version="1.1.1d"),),
            vulnerabilities=(
                Vulnerability(
                    cve_id="CVE-2022-0778",
                    severity="HIGH",
                    description="Test CVE",
                ),
            ),
            sboms=(
                SBOMDocument(
                    format=SBOMFormat.CYCLONEDX_JSON,
                    components=(SBOMComponent(name="openssl", version="1.1.1d"),),
                    content={"bomFormat": "CycloneDX"},
                ),
            ),
            firmware_metadata=FirmwareMetadata(
                architecture="ARM",
                filesystem_type="SquashFS",
                kernel_information="uImage",
                vendor_information="tp-link",
            ),
        )


class _FakeIntelligenceUseCase:
    def execute(self, firmware_path: Path) -> FirmwareIntelligenceResult:
        extraction = ExtractionResult(
            firmware_path=firmware_path,
            extracted_path=Path("sample_data") / "rootfs",
            filesystem_type="SquashFS",
            architecture="ARM",
            metadata={"backend": "fake"},
        )
        scan = ScanResult(
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
        analysis = FirmwareAnalysisResult(
            extraction_result=extraction,
            scan_result=scan,
            firmware_metadata=FirmwareMetadata(
                architecture="ARM",
                filesystem_type="SquashFS",
                kernel_information="uImage",
                vendor_information="tp-link",
            ),
        )
        sboms = GenerateSBOMResult(
            cyclonedx=SBOMDocument(
                format=SBOMFormat.CYCLONEDX_JSON,
                components=(SBOMComponent(name="openssl", version="1.1.1d"),),
                content={"bomFormat": "CycloneDX"},
            ),
            spdx=SBOMDocument(
                format=SBOMFormat.SPDX_JSON,
                components=(SBOMComponent(name="openssl", version="1.1.1d"),),
                content={"spdxVersion": "SPDX-2.3"},
            ),
        )
        return FirmwareIntelligenceResult(analysis=analysis, sboms=sboms, report_id=77)


def test_get_report_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Container, "build_scan_repository", lambda _self: _FakeRepository())

    response = client.get("/reports/7")

    assert response.status_code == 200
    body = response.json()
    assert body["report_id"] == 7
    assert body["risk_score"] == "HIGH"
    assert body["sboms"][0]["format"] == "cyclonedx-json"


def test_firmware_upload_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        Container,
        "build_firmware_intelligence_use_case",
        lambda _self: _FakeIntelligenceUseCase(),
    )

    response = client.post(
        "/firmware/upload",
        files={"firmware_file": ("router.bin", b"firmware-bytes", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["report_id"] == 77
    assert body["risk_score"] == "HIGH"
