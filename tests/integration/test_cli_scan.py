import json
from pathlib import Path

from typer.testing import CliRunner

from app.presentation.cli.main import app

runner = CliRunner()


def test_cli_help_explains_command_selection_and_navigation() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "already extracted root filesystem" in result.stdout
    assert "firmware image file" in result.stdout
    assert "flens <command> --help" in result.stdout


def test_cli_scan_outputs_components_vulnerabilities_and_risk() -> None:
    rootfs_path = Path("sample_data") / "rootfs"

    result = runner.invoke(app, ["scan", str(rootfs_path)])

    assert result.exit_code == 0
    assert "Components:" in result.stdout
    assert "openssl" in result.stdout
    assert "Vulnerabilities:" in result.stdout
    assert "CVE-2022-0778" in result.stdout
    assert "Risk Score:" in result.stdout


def test_cli_scan_writes_spdx_and_cyclonedx_sboms(tmp_path: Path) -> None:
    rootfs_path = Path("sample_data") / "rootfs"
    sbom_out = tmp_path / "nested" / "sbom_output"

    result = runner.invoke(app, ["scan", str(rootfs_path), "--sbom-out", str(sbom_out)])

    assert result.exit_code == 0
    spdx_path = sbom_out / "report.spdx.json"
    cyclonedx_path = sbom_out / "report.cyclonedx.json"
    assert spdx_path.exists()
    assert cyclonedx_path.exists()

    spdx_payload = json.loads(spdx_path.read_text(encoding="utf-8"))
    cyclonedx_payload = json.loads(cyclonedx_path.read_text(encoding="utf-8"))

    assert spdx_payload["spdxVersion"] == "SPDX-2.3"
    assert isinstance(spdx_payload["packages"], list)
    assert any(package["name"] == "openssl" for package in spdx_payload["packages"])

    assert cyclonedx_payload["bomFormat"] == "CycloneDX"
    assert isinstance(cyclonedx_payload["components"], list)
    assert any(component["name"] == "openssl" for component in cyclonedx_payload["components"])
