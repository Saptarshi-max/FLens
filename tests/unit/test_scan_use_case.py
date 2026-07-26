from pathlib import Path

from app.application.services.risk_engine import RiskEngine
from app.application.use_cases.scan_firmware import ScanFirmwareUseCase
from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver
from app.infrastructure.repositories.json_vulnerability_provider import JsonVulnerabilityProvider

FIXTURE_DB = Path(__file__).resolve().parents[1] / "fixtures" / "cve_db_test.json"


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
