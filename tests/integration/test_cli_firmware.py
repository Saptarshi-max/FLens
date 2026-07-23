from pathlib import Path

import pytest
from typer.testing import CliRunner

from app.application.use_cases.analyze_firmware import FirmwareAnalysisResult
from app.config.container import Container
from app.domain.entities.component import Component
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.presentation.cli.main import app

runner = CliRunner()


class _FakeFirmwareAnalysisUseCase:
    def execute(self, firmware_path: Path) -> FirmwareAnalysisResult:
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
        return FirmwareAnalysisResult(extraction_result=extraction, scan_result=scan)


def test_cli_firmware_command_outputs_analysis_and_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        Container,
        "build_firmware_analysis_use_case",
        lambda _self: _FakeFirmwareAnalysisUseCase(),
    )

    firmware_file = tmp_path / "router.bin"
    firmware_file.write_bytes(b"firmware")
    report_file = tmp_path / "firmware_report.html"

    result = runner.invoke(
        app,
        ["firmware", str(firmware_file), "--report-out", str(report_file)],
    )

    assert result.exit_code == 0
    assert "Extraction:" in result.stdout
    assert "Filesystem: SquashFS" in result.stdout
    assert "Risk Score: HIGH" in result.stdout
    assert report_file.exists()
