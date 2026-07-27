"""Write conservative AP96 component identity-resolution artefacts."""

import csv
import json
from pathlib import Path

from app.infrastructure.cpe.component_identity_resolver import ComponentIdentityResolver
from app.infrastructure.parsers.filesystem_component_detector import FileSystemComponentDetector
from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "inventory-benchmarks"
ROOTFS = (
    ROOT
    / "sample_data/extracted"
    / "openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade_extract"
    / "_openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade.bin.extracted"
    / "squashfs-root"
)


def main() -> None:
    components = (
        FileSystemComponentDetector(FirmwareVersionResolver())
        .detect_with_statistics(ROOTFS)
        .components
    )
    resolver = ComponentIdentityResolver()
    rows = []
    for component in components:
        resolution = resolver.resolve(component)
        rows.append(
            {
                "name": component.name,
                "version": component.version,
                "status": resolution.resolution_status,
                "rule_id": resolution.rule_id,
                "cpes": list(resolution.cpe_candidates),
            }
        )
    counts = {
        status: sum(row["status"] == status for row in rows)
        for status in sorted({row["status"] for row in rows})
    }
    payload = {
        "merged_components": len(components),
        "status_counts": counts,
        "resolved_cpe_coverage": sum(bool(row["cpes"]) for row in rows),
        "resolutions": rows,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ap96-identity-resolution.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    with (OUT / "ap96-identity-resolution.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("name", "version", "status", "rule_id", "cpes"))
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "cpes": ";".join(row["cpes"])})
    (OUT / "ap96-identity-resolution.md").write_text(
        "# AP96 identity resolution\n\n"
        + "\n".join(f"- {key}: {value}" for key, value in counts.items())
        + f"\n- resolved CPE coverage: {payload['resolved_cpe_coverage']} / {len(components)}\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
