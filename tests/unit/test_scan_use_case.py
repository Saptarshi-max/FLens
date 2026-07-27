from pathlib import Path

from app.application.services.risk_engine import RiskEngine
from app.application.use_cases.generate_sbom import GenerateSBOMUseCase
from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.domain.entities.component import Component
from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver
from app.infrastructure.repositories.json_vulnerability_provider import JsonVulnerabilityProvider
from app.infrastructure.sbom.json_sbom_generator import JsonSBOMGenerator
from app.presentation.reports.html_report_generator import HtmlReportGenerator

FIXTURE_DB = Path(__file__).resolve().parents[1] / "fixtures" / "cve_db_test.json"


class StaticDetector:
    def __init__(self, components: list[Component]) -> None:
        self._components = components

    def detect(self, rootfs_path: Path) -> list[Component]:
        return list(self._components)


def test_successful_scan(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir(parents=True)
    (tmp_path / "bin" / "openssl").write_text("OpenSSL 1.1.1d", encoding="utf-8")

    use_case = ScanFirmwareUseCase(
        component_detector=FileSystemComponentDetector(FirmwareVersionResolver()),
        vulnerability_provider=JsonVulnerabilityProvider(FIXTURE_DB),
        risk_engine=RiskEngine(),
    )

    result = use_case.execute(tmp_path)

    assert len(result.components) == 1
    assert result.components[0].name == "openssl"
    assert len(result.vulnerabilities) == 2
    assert result.risk_score in {"MEDIUM", "HIGH", "CRITICAL"}


def test_empty_rootfs(tmp_path: Path) -> None:
    use_case = ScanFirmwareUseCase(
        component_detector=FileSystemComponentDetector(FirmwareVersionResolver()),
        vulnerability_provider=JsonVulnerabilityProvider(FIXTURE_DB),
        risk_engine=RiskEngine(),
    )

    result = use_case.execute(tmp_path)

    assert result.components == ()
    assert result.vulnerabilities == ()
    assert result.risk_score == "LOW"


def test_identity_pipeline_reuses_one_scan_result_for_report_and_sboms(tmp_path: Path) -> None:
    use_case = ScanFirmwareUseCase(
        component_detector=StaticDetector(
            [
                Component(
                    "busybox",
                    "1.31.1",
                    cpe="cpe:legacy:busybox",
                    cpe_candidates=("cpe:legacy:other",),
                ),
                Component("uclient-fetch", "1.0"),
            ]
        ),
        vulnerability_provider=JsonVulnerabilityProvider(FIXTURE_DB),
        risk_engine=RiskEngine(),
    )

    result = use_case.execute(tmp_path)
    statistics = result.identity_statistics
    assert statistics is not None
    assert statistics.resolved == 1
    assert statistics.unsupported == 1
    assert statistics.status_total == 2
    assert statistics.governed_cpe_components == 1
    assert statistics.no_cpe_components == 1
    assert statistics.cpe_source_total == 2
    busybox, uclient_fetch = result.components
    assert busybox.name == "busybox"
    assert busybox.version == "1.31.1"
    assert busybox.cpe_source == "governed"
    assert busybox.cpe_candidates == ("cpe:2.3:a:busybox:busybox",)
    assert uclient_fetch.cpe_source == "none"
    assert result.vulnerabilities
    assert all(finding.component_name != "uclient-fetch" for finding in result.vulnerabilities)

    template_dir = Path(__file__).resolve().parents[2] / "app/presentation/reports/templates"
    html = HtmlReportGenerator(template_dir).generate(result, tmp_path / "report.html").read_text(
        encoding="utf-8"
    )
    sboms = GenerateSBOMUseCase(JsonSBOMGenerator()).execute(result)
    cyclonedx = {item["name"]: item for item in sboms.cyclonedx.content["components"]}
    spdx = {item["name"]: item for item in sboms.spdx.content["packages"]}

    assert "governed" in html
    assert cyclonedx["busybox"]["version"] == "1.31.1"
    assert cyclonedx["busybox"]["cpe"] == "cpe:2.3:a:busybox:busybox"
    assert "cpe" not in cyclonedx["uclient-fetch"]
    assert spdx["busybox"]["externalRefs"][0]["referenceLocator"] == (
        "cpe:2.3:a:busybox:busybox"
    )
    assert "externalRefs" not in spdx["uclient-fetch"]
