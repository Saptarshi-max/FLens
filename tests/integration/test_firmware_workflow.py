from dataclasses import dataclass
from pathlib import Path

from app.application.services.risk_engine import RiskEngine
from app.application.use_cases.analyze_firmware import AnalyzeFirmwareUseCase
from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.interfaces.firmware_extractor import FirmwareExtractor
from app.infrastructure.parsers.filesystem_component_detector import FileSystemComponentDetector
from app.infrastructure.parsers.static_version_resolver import StaticVersionResolver
from app.infrastructure.repositories.json_vulnerability_provider import JsonVulnerabilityProvider
from app.presentation.reports.html_report_generator import HtmlReportGenerator


@dataclass
class FakeFirmwareExtractor(FirmwareExtractor):
    extracted_root: Path

    def extract(self, firmware_path: Path) -> ExtractionResult:
        return ExtractionResult(
            firmware_path=firmware_path,
            extracted_path=self.extracted_root,
            filesystem_type="SquashFS",
            architecture="ARM",
            metadata={"backend": "fake"},
        )


def test_firmware_image_to_scan_to_report_workflow(tmp_path: Path) -> None:
    firmware_path = Path("sample_data") / "firmware" / "sample_router.bin"
    extracted_root = Path("sample_data") / "rootfs"
    fixture_db = Path("tests") / "fixtures" / "cve_db_test.json"

    scan_use_case = ScanFirmwareUseCase(
        component_detector=FileSystemComponentDetector(StaticVersionResolver()),
        vulnerability_provider=JsonVulnerabilityProvider(fixture_db),
        risk_engine=RiskEngine(),
    )
    workflow = AnalyzeFirmwareUseCase(
        firmware_extractor=FakeFirmwareExtractor(extracted_root=extracted_root),
        scan_use_case=scan_use_case,
    )

    result = workflow.execute(firmware_path)

    assert result.extraction_result.filesystem_type == "SquashFS"
    assert result.extraction_result.architecture == "ARM"
    assert len(result.scan_result.components) >= 1
    assert result.scan_result.risk_score in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    template_dir = Path("app") / "presentation" / "reports" / "templates"
    report_generator = HtmlReportGenerator(template_dir)
    report_path = report_generator.generate(result.scan_result, tmp_path / "firmware_report.html")

    html = report_path.read_text(encoding="utf-8")
    assert "Risk Score" in html
    assert "CVE" in html
