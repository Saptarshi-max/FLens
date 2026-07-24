import json
import logging
from pathlib import Path
from typing import Annotated

import typer

from app.config.container import Container
from app.domain.entities.scan_result import ScanResult
from app.infrastructure.extraction.errors import ExtractionError

app = typer.Typer(
    help="Analyze embedded Linux firmware for known components and vulnerabilities.",
    epilog="""
Choose a command:
  scan      Use for an already extracted root filesystem directory.
  firmware  Use for a firmware image file (.bin, .img, or .trx); it extracts first.

Examples:
  flens scan sample_data/rootfs --report-out output/rootfs_report.html
  flens firmware router.bin --report-out output/router_report.html

Use `flens <command> --help` for command-specific options. Firmware extraction needs
binwalk and squashfs-tools; use the Docker image when those tools are not installed locally.
""",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
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


def _write_sboms(
    container: Container,
    scan_result: ScanResult,
    output_dir: Path,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    sboms = container.build_generate_sbom_use_case().execute(scan_result)

    spdx_path = output_dir / "report.spdx.json"
    cyclonedx_path = output_dir / "report.cyclonedx.json"

    spdx_path.write_text(json.dumps(sboms.spdx.content, indent=2), encoding="utf-8")
    cyclonedx_path.write_text(json.dumps(sboms.cyclonedx.content, indent=2), encoding="utf-8")

    return spdx_path, cyclonedx_path


@app.command(
    "scan",
    help="""Scan an extracted firmware rootfs directory.

Use this when you already have a directory containing the extracted firmware filesystem,
such as `squashfs-root`. Do not pass a `.bin` firmware image here; use `flens firmware`
instead.

Example: `flens scan sample_data/rootfs --report-out output/rootfs_report.html`
""",
)
def scan(
    rootfs_path: Path,
    report_out: Annotated[
        Path | None,
        typer.Option("--report-out", help="Optional output path for HTML report generation."),
    ] = None,
    sbom_out: Annotated[
        Path | None,
        typer.Option("--sbom-out", help="Optional output directory for SPDX and CycloneDX SBOMs."),
    ] = None,
) -> None:
    container = Container()
    scan_use_case = container.build_scan_use_case()
    scan_result = scan_use_case.execute(rootfs_path)

    _print_scan(scan_result)

    if report_out is not None:
        report_generator = container.build_report_generator()
        report_generator.generate(scan_result, report_out)
        typer.echo(f"\nHTML report written to: {report_out}")

    if sbom_out is not None:
        spdx_path, cyclonedx_path = _write_sboms(container, scan_result, sbom_out)
        typer.echo(f"SBOM (SPDX) written to: {spdx_path}")
        typer.echo(f"SBOM (CycloneDX) written to: {cyclonedx_path}")


@app.command(
    "firmware",
    help="""Extract and scan a firmware image file.

Use this for `.bin`, `.img`, or `.trx` firmware downloads. It runs Binwalk, locates the
extracted root filesystem, then scans it. This command needs binwalk and squashfs-tools;
run it in Docker if those tools are not installed locally.

Example: `flens firmware router.bin --report-out output/router_report.html`
""",
)
def firmware(
    firmware_path: Path,
    report_out: Annotated[
        Path,
        typer.Option("--report-out", help="Output path for HTML report generation."),
    ] = Path("report.html"),
    sbom_out: Annotated[
        Path | None,
        typer.Option("--sbom-out", help="Optional output directory for SPDX and CycloneDX SBOMs."),
    ] = None,
) -> None:
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

    if sbom_out is not None:
        spdx_path, cyclonedx_path = _write_sboms(container, analysis.scan_result, sbom_out)
        typer.echo(f"SBOM (SPDX) written to: {spdx_path}")
        typer.echo(f"SBOM (CycloneDX) written to: {cyclonedx_path}")


if __name__ == "__main__":
    app()
