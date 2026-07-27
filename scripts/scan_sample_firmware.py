"""Batch scan firmware images using FLENS's production application services."""

import argparse
import csv
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

from app.application.use_cases.generate_sbom import GenerateSBOMUseCase
from app.config.container import Container
from app.config.settings import default_settings
from app.infrastructure.extraction.errors import ExtractionError


def discover_firmware(input_dir: Path) -> list[Path]:
    """Return all .bin files below input_dir without following extracted links."""
    files: list[Path] = []
    for directory, _, names in os.walk(input_dir, followlinks=False):
        base = Path(directory)
        files.extend(base / name for name in names if name.lower().endswith(".bin"))
    return sorted(files, key=lambda path: path.as_posix())


def output_name(firmware: Path, input_dir: Path) -> str:
    relative = firmware.relative_to(input_dir).as_posix()
    digest = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:10]
    return f"{firmware.stem}-{digest}"


def _write_summary(path: Path, summary: dict[str, object]) -> None:
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def scan_all(
    input_dir: Path,
    output_dir: Path,
    overwrite: bool = False,
    work_dir: Path | None = None,
) -> list[dict[str, object]]:
    """Extract and scan each image independently, retaining failures as summaries."""
    settings = default_settings()
    container = Container(replace(settings, extraction_work_dir=work_dir) if work_dir else settings)
    analysis_use_case = container.build_firmware_analysis_use_case()
    report_generator = container.build_report_generator()
    sbom_use_case = GenerateSBOMUseCase(container.build_sbom_generator())
    results: list[dict[str, object]] = []

    for firmware in discover_firmware(input_dir):
        relative = firmware.relative_to(input_dir).as_posix()
        destination = output_dir / output_name(firmware, input_dir)
        summary_path = destination / "scan-summary.json"
        if summary_path.exists() and not overwrite:
            results.append(
                {"source_firmware": relative, "status": "skipped", "warnings": ["Output exists."]}
            )
            continue
        try:
            analysis = analysis_use_case.execute(firmware)
        except ExtractionError as exc:
            results.append(
                {
                    "source_firmware": relative,
                    "status": "extraction_failed",
                    "stage": "extraction",
                    "exception_type": type(exc).__name__,
                    "reason": exc.reason,
                    "warnings": [],
                }
            )
            continue
        except OSError as exc:
            results.append(
                {
                    "source_firmware": relative,
                    "status": "scan_failed",
                    "stage": "scan",
                    "exception_type": type(exc).__name__,
                    "reason": str(exc),
                    "warnings": [],
                }
            )
            continue

        try:
            destination.mkdir(parents=True, exist_ok=True)
            report = report_generator.generate(analysis.scan_result, destination / "report.html")
            sboms = sbom_use_case.execute(analysis.scan_result)
            cyclonedx = destination / "cyclonedx.json"
            spdx = destination / "spdx.json"
            cyclonedx.write_text(json.dumps(sboms.cyclonedx.content, indent=2), encoding="utf-8")
            spdx.write_text(json.dumps(sboms.spdx.content, indent=2), encoding="utf-8")
            stats = analysis.scan_result.inventory_statistics
            identity = analysis.scan_result.identity_statistics
            summary = {
                "source_firmware": relative,
                "status": "succeeded",
                "extraction_status": "succeeded",
                "scan_status": "succeeded",
                "merged_component_count": (
                    stats.merged_components if stats else len(analysis.scan_result.components)
                ),
                "known_version_count": stats.components_with_known_versions if stats else None,
                "unknown_version_count": stats.components_with_unknown_versions if stats else None,
                "resolved_identity_count": identity.resolved if identity else None,
                "governed_cpe_count": identity.governed_cpe_components if identity else None,
                "legacy_cpe_count": identity.legacy_cpe_components if identity else None,
                "no_cpe_count": identity.no_cpe_components if identity else None,
                "vulnerability_count": len(analysis.scan_result.vulnerabilities),
                "artefacts": {
                    "report": str(report),
                    "cyclonedx": str(cyclonedx),
                    "spdx": str(spdx),
                    "summary": str(summary_path),
                },
                "warnings": [],
            }
            _write_summary(summary_path, summary)
            results.append(summary)
        except OSError as exc:
            results.append(
                {
                    "source_firmware": relative,
                    "status": "report_generation_failed",
                    "stage": "report_generation",
                    "exception_type": type(exc).__name__,
                    "reason": str(exc),
                    "warnings": [],
                }
            )
    return results


def write_batch_summary(output_dir: Path, results: list[dict[str, object]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(results, key=lambda item: str(item["source_firmware"]))
    counts = {status: sum(item["status"] == status for item in ordered) for status in (
        "succeeded", "extraction_failed", "scan_failed", "report_generation_failed", "skipped"
    )}
    payload = {"total_firmware_files": len(ordered), **counts, "results": ordered}
    _write_summary(output_dir / "batch-summary.json", payload)
    with (output_dir / "batch-summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("source_firmware", "status", "stage", "reason"))
        writer.writeheader()
        for item in ordered:
            writer.writerow({key: item.get(key, "") for key in writer.fieldnames})
    (output_dir / "README.md").write_text(
        "# Sample firmware batch scan\n\n"
        "Generated by `python scripts/scan_sample_firmware.py`. Failed extractions do not "
        "have reports.\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-scan .bin sample firmware images.")
    parser.add_argument("--input-dir", type=Path, default=Path("sample_data"))
    parser.add_argument("--output-dir", type=Path, default=Path("output/sample-scans"))
    parser.add_argument("--work-dir", type=Path, help="Linux-local extraction workspace.")
    parser.add_argument("--overwrite", action="store_true")
    arguments = parser.parse_args()
    results = scan_all(
        arguments.input_dir,
        arguments.output_dir,
        arguments.overwrite,
        arguments.work_dir,
    )
    write_batch_summary(arguments.output_dir, results)
    print(f"Processed {len(results)} firmware image(s).")


if __name__ == "__main__":
    main()
