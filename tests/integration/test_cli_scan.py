from pathlib import Path

from typer.testing import CliRunner

from app.presentation.cli.main import app

runner = CliRunner()


def test_cli_scan_outputs_components_vulnerabilities_and_risk() -> None:
    rootfs_path = Path("sample_data") / "rootfs"

    result = runner.invoke(app, ["scan", str(rootfs_path)])

    assert result.exit_code == 0
    assert "Components:" in result.stdout
    assert "openssl" in result.stdout
    assert "Vulnerabilities:" in result.stdout
    assert "CVE-2022-0778" in result.stdout
    assert "Risk Score:" in result.stdout
