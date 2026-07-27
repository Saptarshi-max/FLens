"""Produce deterministic, evidence-backed CPE coverage artefacts for AP96."""

import csv
import json
from dataclasses import asdict
from pathlib import Path

from app.domain.entities.component import Component
from app.infrastructure.elf.inventory_scanner import ElfInventoryScanner
from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "inventory-benchmarks"
AP96_ROOTFS = (
    ROOT
    / "sample_data"
    / "extracted"
    / "openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade_extract"
    / "_openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade.bin.extracted"
    / "squashfs-root"
)
INTENTIONAL_EXCLUSIONS = {
    "firewall": "OpenWrt framework package; no direct upstream product identity.",
    "fw3": "OpenWrt firewall utility; no direct upstream product identity.",
    "luci-app-firewall": "OpenWrt UI integration, not an upstream vulnerability product.",
}
RECOMMENDATIONS = (
    {
        "component": "hostapd-common",
        "recommendation": "Review alias to hostapd only with package-role evidence.",
        "reason": "The package is a hostapd split component, not the hostapd daemon itself.",
    },
    {
        "component": "kernel",
        "recommendation": "Add a separately governed Linux kernel CPE policy.",
        "reason": "Kernel CPE matching needs platform and downstream patch context.",
    },
    {
        "component": "wpad-basic",
        "recommendation": (
            "Do not alias automatically; inspect bundled hostapd/wpa_supplicant versions."
        ),
        "reason": "The OpenWrt package bundles multiple upstream products.",
    },
    {
        "component": "uclient-fetch",
        "recommendation": (
            "Keep distinct from curl and wget unless banner or package evidence identifies either."
        ),
        "reason": "It is an OpenWrt HTTP client with no demonstrated curl/wget identity.",
    },
    {
        "component": "libc",
        "recommendation": "Determine musl versus glibc from package/build evidence before mapping.",
        "reason": "A generic libc package name is insufficient for a CPE choice.",
    },
)


def _component_record(component: Component, category: str) -> dict[str, object]:
    return {
        "category": category,
        "name": component.name,
        "version": component.version,
        "component_type": component.component_type,
        "cpe_candidates": list(component.cpe_candidates),
        "evidence_sources": sorted({evidence.source for evidence in component.evidence}),
    }


def _diagnostics() -> dict[str, object]:
    scan = ElfInventoryScanner().scan(AP96_ROOTFS)
    return {
        "counts": {
            "malformed": scan.malformed_elf_files,
            "unreadable": scan.unreadable_files,
            "unsupported": scan.unsupported_elf_files,
        },
        "samples": {
            "malformed": [asdict(item) for item in scan.malformed_diagnostics],
            "unreadable": [asdict(item) for item in scan.unreadable_diagnostics],
            "unsupported": [asdict(item) for item in scan.unsupported_diagnostics],
        },
    }


def _readme(analysis: dict[str, object]) -> str:
    categories = analysis["categories"]
    lines = [
        "# AP96 CPE coverage analysis",
        "",
        "| Category | Components |",
        "|---|---:|",
    ]
    for name in ("with_cpe_candidates", "known_versions_without_cpe", "unknown_versions"):
        lines.append(f"| {name} | {len(categories[name])} |")
    lines.extend(["", "## High-value components", ""])
    for record in analysis["high_value_components"]:
        cpes = ", ".join(record["cpe_candidates"]) or "none"
        lines.append(f"- `{record['name']}` {record['version']}: {cpes}")
    lines.extend(["", "## Evidence-backed mapping recommendations", ""])
    for recommendation in analysis["mapping_recommendations"]:
        lines.append(
            f"- `{recommendation['component']}` - {recommendation['recommendation']} "
            f"({recommendation['reason']})"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    components = FileSystemComponentDetector(
        FirmwareVersionResolver()
    ).detect_with_statistics(AP96_ROOTFS).components
    categories = {
        "with_cpe_candidates": [
            _component_record(component, "with_cpe_candidates")
            for component in components
            if component.cpe_candidates
        ],
        "known_versions_without_cpe": [
            _component_record(component, "known_versions_without_cpe")
            for component in components
            if component.version != "Unknown" and not component.cpe_candidates
        ],
        "unknown_versions": [
            _component_record(component, "unknown_versions")
            for component in components
            if component.version == "Unknown"
        ],
        "intentionally_excluded": [
            {"name": name, "reason": reason}
            for name, reason in sorted(INTENTIONAL_EXCLUSIONS.items())
        ],
    }
    high_value = [
        _component_record(component, "high_value")
        for component in components
        if component.name.lower()
        in {
            "busybox",
            "dnsmasq",
            "dropbear",
            "hostapd-common",
            "kernel",
            "firewall",
            "fw3",
            "wpad-basic",
            "uclient-fetch",
        }
    ]
    analysis = {
        "firmware": "openwrt-ap96-19.07.10.bin",
        "rootfs": AP96_ROOTFS.relative_to(ROOT).as_posix(),
        "merged_component_count": len(components),
        "categories": categories,
        "high_value_components": high_value,
        "mapping_recommendations": list(RECOMMENDATIONS),
        "not_detected": ["openssl", "libssl", "curl", "wget", "hostapd"],
        "elf_diagnostics": _diagnostics(),
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "ap96-cpe-coverage.json").write_text(
        json.dumps(analysis, indent=2) + "\n", encoding="utf-8"
    )
    rows = [
        record
        for records in categories.values()
        if isinstance(records, list)
        for record in records
    ]
    with (OUTPUT / "ap96-cpe-coverage.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "category",
                "name",
                "version",
                "component_type",
                "cpe_candidates",
                "evidence_sources",
            ),
        )
        writer.writeheader()
        for row in rows:
            if "category" in row:
                writer.writerow(
                    {
                        **row,
                        "cpe_candidates": ";".join(row["cpe_candidates"]),
                        "evidence_sources": ";".join(row["evidence_sources"]),
                    }
                )
    (OUTPUT / "ap96-cpe-coverage.md").write_text(_readme(analysis), encoding="utf-8")


if __name__ == "__main__":
    main()
