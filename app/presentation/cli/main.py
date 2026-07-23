import logging
from pathlib import Path
from typing import Annotated

import typer

from app.config.container import Container
from app.domain.entities.scan_result import ScanResult
from app.infrastructure.extraction.errors import ExtractionError

app = typer.Typer(help="FLENS Firmware Linux Embedded Security CLI")
logger = logging.getLogger(__name__)


@app.callback()
def main() -> None:
    """FLENS command group."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def _print_scan(scan_result: ScanResult) -> None:
    # Keep output plain and test-friendly for Phase 1.
    typer.echo("Components:")
    for component in scan_result.components:
        typer.echo(f"- {component.name}: {component.version}")

    typer.echo("\nVulnerabilities:")
    for vulnerability in scan_result.vulnerabilities:
        typer.echo(
            f"- {vulnerability.cve_id} "
            f"[{vulnerability.severity}] {vulnerability.description}"
        )

    typer.echo(f"\nRisk Score: {scan_result.risk_score}")


@app.command("scan")
def scan(
    rootfs_path: Path,
    report_out: Annotated[
        Path | None,
        typer.Option("--report-out", help="Optional output path for HTML report generation."),
    ] = None,
) -> None:
    """Scan an extracted firmware rootfs directory."""
    container = Container()
    scan_use_case = container.build_scan_use_case()
    scan_result = scan_use_case.execute(rootfs_path)

    _print_scan(scan_result)

    if report_out is not None:
        report_generator = container.build_report_generator()
        report_generator.generate(scan_result, report_out)
        typer.echo(f"\nHTML report written to: {report_out}")


@app.command("firmware")
def firmware(
    firmware_path: Path,
    report_out: Annotated[
        Path,
        typer.Option("--report-out", help="Output path for HTML report generation."),
    ] = Path("report.html"),
) -> None:
    """Extract and scan a firmware image file."""
    container = Container()
    analyze_firmware_use_case = container.build_firmware_analysis_use_case()

    try:
        analysis = analyze_firmware_use_case.execute(firmware_path)
    except ExtractionError as exc:
        typer.echo("ERROR:\n")
        typer.echo("Unable to extract firmware.\n")
        typer.echo("Reason:")
        typer.echo(exc.reason)
        raise typer.Exit(code=1) from exc

    logger.info("Starting component scan")
    typer.echo("Extraction:")
    typer.echo(f"- Firmware: {analysis.extraction_result.firmware_path}")
    typer.echo(f"- Extracted Path: {analysis.extraction_result.extracted_path}")
    typer.echo(f"- Filesystem: {analysis.extraction_result.filesystem_type}")
    typer.echo(f"- Architecture: {analysis.extraction_result.architecture}")
    typer.echo()

    _print_scan(analysis.scan_result)

    report_generator = container.build_report_generator()
    report_generator.generate(analysis.scan_result, report_out)
    typer.echo(f"\nHTML report written to: {report_out}")


if __name__ == "__main__":
    app()
