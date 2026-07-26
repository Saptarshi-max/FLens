from app.application.services.risk_engine import RiskEngine
from app.application.use_cases.analyze_firmware import AnalyzeFirmwareUseCase
from app.application.use_cases.analyze_firmware_intelligence import (
    AnalyzeFirmwareIntelligenceUseCase,
)
from app.application.use_cases.generate_sbom import GenerateSBOMUseCase
from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.application.use_cases.store_scan import StoreScanUseCase
from app.config.settings import AppSettings, default_settings
from app.infrastructure.database.engine import create_database_engine, create_session_factory
from app.infrastructure.database.repository import SQLAlchemyScanRepository
from app.infrastructure.elf.elf_analyzer import ELFAnalyzer
from app.infrastructure.extraction.binwalk_extractor import BinwalkExtractor
from app.infrastructure.extraction.firmware_metadata_extractor import (
    RootfsFirmwareMetadataExtractor,
)
from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver
from app.infrastructure.repositories.json_vulnerability_provider import (
    JsonVulnerabilityFeed,
    JsonVulnerabilityProvider,
    NvdVulnerabilityFeed,
    OsvVulnerabilityFeed,
)
from app.infrastructure.sbom.json_sbom_generator import JsonSBOMGenerator
from app.presentation.reports.html_report_generator import HtmlReportGenerator


class Container:
    """Simple composition root for dependency construction."""

    def __init__(self, settings: AppSettings | None = None) -> None:
        self.settings = settings or default_settings()

    def build_scan_use_case(self) -> ScanFirmwareUseCase:
        version_resolver = FirmwareVersionResolver()
        detector = FileSystemComponentDetector(version_resolver, elf_analyzer=ELFAnalyzer())
        feed_types = {
            "json": JsonVulnerabilityFeed,
            "nvd": NvdVulnerabilityFeed,
            "osv": OsvVulnerabilityFeed,
        }
        feeds = tuple(
            feed_types[name](self.settings.cve_database_path)
            for name in self.settings.feeds
            if name in feed_types
        )
        vulnerability_provider = JsonVulnerabilityProvider(self.settings.cve_database_path, feeds)
        risk_engine = RiskEngine()
        return ScanFirmwareUseCase(detector, vulnerability_provider, risk_engine)

    def build_report_generator(self) -> HtmlReportGenerator:
        return HtmlReportGenerator(
            template_dir=self.settings.report_template_dir,
            repository_url=self.settings.repository_url,
        )

    def build_firmware_extractor(self) -> BinwalkExtractor:
        return BinwalkExtractor(work_dir=self.settings.extraction_work_dir)

    def build_firmware_analysis_use_case(self) -> AnalyzeFirmwareUseCase:
        return AnalyzeFirmwareUseCase(
            firmware_extractor=self.build_firmware_extractor(),
            scan_use_case=self.build_scan_use_case(),
            firmware_metadata_extractor=RootfsFirmwareMetadataExtractor(),
        )

    def build_scan_repository(self) -> SQLAlchemyScanRepository:
        engine = create_database_engine(self.settings.database_path)
        session_factory = create_session_factory(engine)
        return SQLAlchemyScanRepository(session_factory=session_factory)

    def build_sbom_generator(self) -> JsonSBOMGenerator:
        return JsonSBOMGenerator()

    def build_generate_sbom_use_case(self) -> GenerateSBOMUseCase:
        return GenerateSBOMUseCase(sbom_generator=self.build_sbom_generator())

    def build_store_scan_use_case(self) -> StoreScanUseCase:
        return StoreScanUseCase(scan_repository=self.build_scan_repository())

    def build_firmware_intelligence_use_case(self) -> AnalyzeFirmwareIntelligenceUseCase:
        return AnalyzeFirmwareIntelligenceUseCase(
            analyze_firmware_use_case=self.build_firmware_analysis_use_case(),
            generate_sbom_use_case=self.build_generate_sbom_use_case(),
            store_scan_use_case=self.build_store_scan_use_case(),
        )
