from app.application.services.risk_engine import RiskEngine
from app.application.use_cases.analyze_firmware import AnalyzeFirmwareUseCase
from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.config.settings import AppSettings, default_settings
from app.infrastructure.extraction.binwalk_extractor import BinwalkExtractor
from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.static_version_resolver import StaticVersionResolver
from app.infrastructure.repositories.json_vulnerability_provider import (
    JsonVulnerabilityProvider,
)
from app.presentation.reports.html_report_generator import HtmlReportGenerator


class Container:
    """Simple composition root for dependency construction."""

    def __init__(self, settings: AppSettings | None = None) -> None:
        self.settings = settings or default_settings()

    def build_scan_use_case(self) -> ScanFirmwareUseCase:
        version_resolver = StaticVersionResolver()
        detector = FileSystemComponentDetector(version_resolver)
        vulnerability_provider = JsonVulnerabilityProvider(self.settings.cve_database_path)
        risk_engine = RiskEngine()
        return ScanFirmwareUseCase(detector, vulnerability_provider, risk_engine)

    def build_report_generator(self) -> HtmlReportGenerator:
        return HtmlReportGenerator(template_dir=self.settings.report_template_dir)

    def build_firmware_extractor(self) -> BinwalkExtractor:
        return BinwalkExtractor(work_dir=self.settings.extraction_work_dir)

    def build_firmware_analysis_use_case(self) -> AnalyzeFirmwareUseCase:
        return AnalyzeFirmwareUseCase(
            firmware_extractor=self.build_firmware_extractor(),
            scan_use_case=self.build_scan_use_case(),
        )
