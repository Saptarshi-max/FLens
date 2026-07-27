"""Render configured FLENS validation reports as browser-quality PDF documents.

The script intentionally loads only local ``file:`` resources. It does not alter the
source reports and does not make network requests while rendering.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReportSpec:
    """One repository-relative HTML input and its stable PDF target."""

    identifier: str
    firmware: str
    original_input: str
    html_path: Path
    pdf_path: Path


REPORTS: tuple[ReportSpec, ...] = (
    ReportSpec(
        "archer-c7-v5",
        "TP-Link Archer C7 v5",
        "c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin",
        Path(
            "output/sample-scans/c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43-5fd4c55b5f/report.html"
        ),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-archer-c7-v5-report.pdf"),
    ),
    ReportSpec(
        "carambola2",
        "8devices Carambola 2",
        "carambola2-sysupgrade.bin",
        Path("output/sample-scans/carambola2-sysupgrade-79215be2ef/report.html"),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-carambola2-report.pdf"),
    ),
    ReportSpec(
        "netgear-r6400v2-ddwrt",
        "Netgear R6400v2 DD-WRT",
        "firmware/dd-wrt/netgear-r6400v2-webflash.bin",
        Path("output/sample-scans/netgear-r6400v2-webflash-67b941d30f/report.html"),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-netgear-r6400v2-ddwrt-report.pdf"),
    ),
    ReportSpec(
        "netgear-r7000-ddwrt",
        "Netgear R7000 DD-WRT",
        "firmware/dd-wrt/netgear-r7000-webflash.bin",
        Path("output/sample-scans/netgear-r7000-webflash-ccc222648b/report.html"),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-netgear-r7000-ddwrt-report.pdf"),
    ),
    ReportSpec(
        "openwrt-ap96-19.07.10",
        "ALFA AP96 OpenWrt 19.07.10",
        "firmware/openwrt/openwrt-ap96-19.07.10.bin",
        Path("output/sample-scans/openwrt-ap96-19.07.10-54b90d4297/report.html"),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-ap96-19.07.10-report.pdf"),
    ),
    ReportSpec(
        "openwrt-meraki-mr16-19.07.10",
        "Meraki MR16 OpenWrt 19.07.10",
        "firmware/openwrt/openwrt-meraki-mr16-19.07.10.bin",
        Path("output/sample-scans/openwrt-meraki-mr16-19.07.10-63e2a31c9d/report.html"),
        Path(
            "docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-meraki-mr16-19.07.10-report.pdf"
        ),
    ),
    ReportSpec(
        "openwrt-onion-omega-19.07.10",
        "Onion Omega OpenWrt 19.07.10",
        "firmware/openwrt/openwrt-onion-omega-19.07.10.bin",
        Path("output/sample-scans/openwrt-onion-omega-19.07.10-d0dddc1288/report.html"),
        Path(
            "docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-onion-omega-19.07.10-report.pdf"
        ),
    ),
    ReportSpec(
        "openwrt-packet-squirrel-19.07.10",
        "Packet Squirrel OpenWrt 19.07.10",
        "firmware/openwrt/openwrt-packet-squirrel-19.07.10.bin",
        Path("output/sample-scans/openwrt-packet-squirrel-19.07.10-5f93ebe640/report.html"),
        Path(
            "docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-packet-squirrel-19.07.10-report.pdf"
        ),
    ),
    ReportSpec(
        "linksys-ea6500-ddwrt",
        "Linksys EA6500 DD-WRT",
        "linksys_ea6500_ddwrt.bin",
        Path("output/sample-scans/linksys_ea6500_ddwrt-9ab0a1428c/report.html"),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-linksys-ea6500-ddwrt-report.pdf"),
    ),
    ReportSpec(
        "openwrt-ap96-sysupgrade-19.07.10",
        "ALFA AP96 sysupgrade OpenWrt 19.07.10",
        "openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade.bin",
        Path(
            "output/sample-scans/openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade-5794181e85/report.html"
        ),
        Path(
            "docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-ap96-sysupgrade-19.07.10-report.pdf"
        ),
    ),
    ReportSpec(
        "tplink-tl-wa701nd-v2",
        "TP-Link TL-WA701ND v2",
        "wa701nv2_en_3_17_0_up_boot(140324).bin",
        Path("output/sample-scans/wa701nv2_en_3_17_0_up_boot(140324)-5ac5257880/report.html"),
        Path("docs/release-evidence/v0.3.0-alpha/reports/flens-tplink-tl-wa701nd-v2-report.pdf"),
    ),
)


RenderFunction = Callable[[Path, Path], None]


def repository_root(start: Path | None = None) -> Path:
    """Find the repository root without relying on a machine-specific path."""
    for candidate in (start or Path(__file__)).resolve().parents:
        if (candidate / ".git").exists() and (candidate / "pyproject.toml").exists():
            return candidate
    raise RuntimeError("Could not locate the repository root.")


def validate_reports(reports: Iterable[ReportSpec]) -> tuple[ReportSpec, ...]:
    """Reject ambiguous report IDs or output paths before conversion begins."""
    validated = tuple(reports)
    identifiers = [report.identifier for report in validated]
    outputs = [report.pdf_path.as_posix() for report in validated]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Duplicate report identifiers are not allowed.")
    if len(outputs) != len(set(outputs)):
        raise ValueError("Duplicate PDF targets are not allowed.")
    return validated


def select_reports(reports: Iterable[ReportSpec], identifier: str | None) -> tuple[ReportSpec, ...]:
    """Return all reports or exactly one configured report."""
    validated = validate_reports(reports)
    if identifier is None:
        return validated
    selected = tuple(report for report in validated if report.identifier == identifier)
    if not selected:
        raise ValueError(f"Unknown report ID: {identifier}")
    return selected


def render_with_playwright(html_path: Path, pdf_path: Path) -> None:
    """Use local headless Chromium rendering and leave the HTML source unchanged."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError(
            "Playwright is not installed. Run `uv sync --extra dev` and "
            "`uv run playwright install chromium`."
        ) from error

    print_css = """
        *, *::before, *::after { animation: none !important; transition: none !important; }
        details { display: block !important; }
        details > * { display: block !important; }
        [hidden] { display: block !important; }
        [style*='overflow'] { overflow: visible !important; }
        [style*='height'] { height: auto !important; max-height: none !important; }
        section, .panel, table, tr { break-inside: avoid; page-break-inside: avoid; }
        h1, h2, h3 { break-after: avoid; page-break-after: avoid; }
        table { width: 100% !important; }
    """

    browser_executable = os.environ.get("FLENS_CHROMIUM_EXECUTABLE")
    with sync_playwright() as playwright:
        browser = (
            playwright.chromium.launch(headless=True, executable_path=browser_executable)
            if browser_executable
            else playwright.chromium.launch(headless=True)
        )
        try:
            page = browser.new_page()
            page.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(("file:", "data:"))
                    else route.abort()
                ),
            )
            page.goto(html_path.resolve().as_uri(), wait_until="load")
            page.wait_for_load_state("networkidle")
            page.evaluate("() => document.fonts ? document.fonts.ready : Promise.resolve()")
            page.evaluate(
                """() => {
                    document.querySelectorAll('details').forEach((item) => { item.open = true; });
                    document.querySelectorAll('[hidden]').forEach((item) => {
                        item.hidden = false;
                    });
                }"""
            )
            page.add_style_tag(content=print_css)
            page.emulate_media(media="screen")
            pdf_path.parent.mkdir(parents=True, exist_ok=True)
            page.pdf(
                path=str(pdf_path),
                format="A4",
                landscape=True,
                margin={"top": "12mm", "right": "10mm", "bottom": "12mm", "left": "10mm"},
                print_background=True,
                display_header_footer=False,
            )
        finally:
            browser.close()


def convert_reports(
    root: Path,
    reports: Iterable[ReportSpec],
    *,
    overwrite: bool,
    renderer: RenderFunction = render_with_playwright,
) -> int:
    """Convert reports, returning a non-zero status when any requested report fails."""
    failures = 0
    for report in validate_reports(reports):
        html_path = root / report.html_path
        pdf_path = root / report.pdf_path
        if not html_path.is_file():
            print(f"FAIL {report.identifier}: missing HTML input: {html_path}")
            failures += 1
            continue
        if pdf_path.exists() and not overwrite:
            print(f"SKIP {report.identifier}: PDF already exists (use --overwrite): {pdf_path}")
            continue
        try:
            print(f"CONVERT {report.identifier}: {html_path} -> {pdf_path}")
            renderer(html_path, pdf_path)
            if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
                raise RuntimeError("Renderer did not produce a non-empty PDF.")
        except Exception as error:  # Individual reports must not stop the batch.
            print(f"FAIL {report.identifier}: {error}")
            failures += 1
    return 1 if failures else 0


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="Convert one configured report ID.")
    parser.add_argument("--list", action="store_true", help="List configured reports and exit.")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing PDF.")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    reports = validate_reports(REPORTS)
    if args.list:
        for report in reports:
            print(f"{report.identifier}\n  HTML: {report.html_path}\n  PDF:  {report.pdf_path}")
        return 0
    try:
        selected = select_reports(reports, args.report)
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return convert_reports(repository_root(), selected, overwrite=args.overwrite)


if __name__ == "__main__":
    raise SystemExit(main())
