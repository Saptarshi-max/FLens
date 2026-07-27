from pathlib import Path

from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence
from app.infrastructure.elf.inventory_scanner import ElfScanResult
from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.firmware_version_resolver import FirmwareVersionResolver
from app.infrastructure.parsers.package_database import PackageRecord


class _PackageParser:
    def __init__(self, records: tuple[PackageRecord, ...]) -> None:
        self._records = records

    def parse(self, rootfs_path: Path) -> tuple[PackageRecord, ...]:
        return self._records


class _ElfScanner:
    def __init__(self, result: ElfScanResult) -> None:
        self._result = result

    def scan(self, rootfs_path: Path) -> ElfScanResult:
        return self._result


def _package(name: str, version: str) -> PackageRecord:
    return PackageRecord(
        name,
        version,
        Evidence("opkg", "/usr/lib/opkg/status", f"Package: {name}"),
    )


def _elf_component(name: str, version: str = "Unknown") -> Component:
    return Component(
        name=name,
        version=version,
        component_type="executable",
        evidence=(Evidence("elf_metadata", f"/bin/{name}", name),),
    )


def _detector(
    records: tuple[PackageRecord, ...] = (), result: ElfScanResult | None = None
) -> FileSystemComponentDetector:
    detector = FileSystemComponentDetector(FirmwareVersionResolver())
    detector._package_parser = _PackageParser(records)
    detector._elf_inventory = _ElfScanner(result or ElfScanResult(()))
    return detector


def test_empty_filesystem_statistics(tmp_path: Path) -> None:
    result = _detector().detect_with_statistics(tmp_path)

    assert result.components == ()
    assert result.statistics.raw_components_discovered == 0
    assert result.statistics.merged_components == 0
    assert result.statistics.components_with_known_versions == 0
    assert result.statistics.components_with_unknown_versions == 0


def test_package_only_statistics_track_known_and_unknown_versions(tmp_path: Path) -> None:
    result = _detector(
        (_package("curl", "8.0"), _package("custom", "Unknown"))
    ).detect_with_statistics(tmp_path)

    statistics = result.statistics
    assert statistics.package_records_discovered == 2
    assert statistics.package_components_discovered == 2
    assert statistics.raw_components_discovered == 2
    assert statistics.merged_components == 2
    assert statistics.components_with_known_versions == 1
    assert statistics.components_with_unknown_versions == 1
    assert statistics.components_with_cpe_candidates == 1


def test_elf_only_statistics_are_propagated_from_scan_result(tmp_path: Path) -> None:
    elf_result = ElfScanResult(
        (_elf_component("tool", "1.0"),),
        files_examined=8,
        executables_detected=1,
        libraries_detected=2,
        non_elf_files_skipped=3,
        symlinks_skipped=4,
        oversized_files_skipped=5,
        malformed_elf_files=6,
        unreadable_files=7,
        unsupported_elf_files=8,
        discovery_limit_reached=True,
    )

    statistics = _detector(result=elf_result).detect_with_statistics(tmp_path).statistics

    assert statistics.elf_files_examined == 8
    assert statistics.elf_executables_discovered == 1
    assert statistics.elf_libraries_discovered == 2
    assert statistics.elf_non_elf_files_skipped == 3
    assert statistics.elf_symlinks_skipped == 4
    assert statistics.elf_oversized_files_skipped == 5
    assert statistics.elf_malformed_files == 6
    assert statistics.elf_unreadable_files == 7
    assert statistics.elf_unsupported_files == 8
    assert statistics.elf_discovery_limit_reached is True


def test_mixed_inventory_counts_raw_components_before_merging(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "busybox").write_text("not an ELF", encoding="utf-8")
    result = _detector(
        (_package("curl", "8.0"),),
        ElfScanResult((_elf_component("busybox", "1.35"),)),
    ).detect_with_statistics(tmp_path)

    statistics = result.statistics
    assert statistics.known_binary_components_discovered == 1
    assert statistics.package_components_discovered == 1
    assert statistics.raw_components_discovered == 3
    assert statistics.merged_components == 2
    assert statistics.components_with_known_versions == 2
    assert statistics.components_with_unknown_versions == 0
    assert statistics.components_with_cpe_candidates == 2


def test_statistics_are_deterministic_regardless_of_package_order(tmp_path: Path) -> None:
    records = (_package("curl", "8.0"), _package("custom", "Unknown"))

    first = _detector(records).detect_with_statistics(tmp_path)
    second = _detector(tuple(reversed(records))).detect_with_statistics(tmp_path)

    assert first == second
