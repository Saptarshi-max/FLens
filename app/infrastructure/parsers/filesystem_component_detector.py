import os
from pathlib import Path

from app.domain.entities.component import Component
from app.domain.entities.inventory import InventoryResult, InventoryStatistics
from app.domain.interfaces.component_detector import ComponentDetector
from app.domain.interfaces.version_resolver import VersionResolver
from app.infrastructure.cpe.resolver import CpeResolver
from app.infrastructure.elf.elf_analyzer import ELFAnalyzer
from app.infrastructure.elf.inventory_scanner import ElfInventoryScanner, ElfScanResult
from app.infrastructure.inventory.inventory_merger import InventoryMerger
from app.infrastructure.parsers.package_database import PackageDatabaseParser


class FileSystemComponentDetector(ComponentDetector):
    """Detect known components by filename within extracted rootfs."""

    def __init__(
        self,
        version_resolver: VersionResolver,
        elf_analyzer: ELFAnalyzer | None = None,
    ) -> None:
        self._version_resolver = version_resolver
        self._elf_analyzer = elf_analyzer
        self._cpe_resolver = CpeResolver()
        self._package_parser = PackageDatabaseParser()
        self._elf_inventory = ElfInventoryScanner()
        self._inventory_merger = InventoryMerger()
        self._supported_binaries = {"busybox", "openssl", "dropbear"}

    def detect(self, rootfs_path: Path) -> list[Component]:
        """Return components for existing callers without statistics coupling."""
        return list(self.detect_with_statistics(rootfs_path).components)

    def detect_with_statistics(self, rootfs_path: Path) -> InventoryResult:
        """Return the inventory and counts from this single detector invocation."""
        if not rootfs_path.exists() or not rootfs_path.is_dir():
            return InventoryResult((), InventoryStatistics())

        discovered: dict[str, list[Path]] = {}
        for directory, _, filenames in os.walk(rootfs_path, followlinks=False):
            for filename in filenames:
                file_path = Path(directory) / filename
                try:
                    if file_path.is_symlink() or not file_path.is_file():
                        continue
                except OSError:
                    continue
                binary_name = file_path.name.lower()
                if binary_name in self._supported_binaries:
                    discovered.setdefault(binary_name, []).append(file_path)
                    continue

                if self._elf_analyzer is None:
                    continue

                analysis = self._elf_analyzer.analyze(file_path)
                if analysis is not None and analysis.inferred_component in self._supported_binaries:
                    discovered.setdefault(analysis.inferred_component, []).append(file_path)

        known_binary_components = [
            self._cpe_resolver.resolve(
                Component(
                    name=name,
                    version=resolution.version,
                    evidence=resolution.evidence,
                    confidence=resolution.confidence,
                )
            )
            for name, paths in sorted(discovered.items())
            for resolution in [self._version_resolver.resolve(name, rootfs_path, tuple(paths))]
        ]
        existing = {component.name for component in known_binary_components}
        package_records = self._package_parser.parse(rootfs_path)
        package_components: list[Component] = []
        for package in package_records:
            if package.name not in existing:
                package_components.append(
                    self._cpe_resolver.resolve(
                        Component(
                            name=package.name,
                            version=package.version,
                            evidence=(package.evidence,),
                            confidence="HIGH",
                            component_type="package",
                            architecture=package.architecture,
                            dependencies=package.dependencies,
                        )
                    )
                )
        elf_result = self._elf_inventory.scan(rootfs_path)
        raw_components = (
            known_binary_components + package_components + list(elf_result.components)
        )
        merged_components = self._inventory_merger.merge(raw_components)
        return InventoryResult(
            components=tuple(merged_components),
            statistics=self._statistics(
                package_record_count=len(package_records),
                package_component_count=len(package_components),
                known_binary_component_count=len(known_binary_components),
                elf_result=elf_result,
                merged_components=merged_components,
            ),
            diagnostics=tuple(
                (item.path, item.exception_type, item.reason)
                for item in (
                    elf_result.malformed_diagnostics
                    + elf_result.unreadable_diagnostics
                    + elf_result.unsupported_diagnostics
                    + elf_result.entry_diagnostics
                )
            ),
        )

    @staticmethod
    def _statistics(
        *,
        package_record_count: int,
        package_component_count: int,
        known_binary_component_count: int,
        elf_result: ElfScanResult,
        merged_components: list[Component],
    ) -> InventoryStatistics:
        known_versions = sum(
            component.version != "Unknown" for component in merged_components
        )
        return InventoryStatistics(
            package_records_discovered=package_record_count,
            package_components_discovered=package_component_count,
            known_binary_components_discovered=known_binary_component_count,
            elf_files_examined=elf_result.files_examined,
            elf_executables_discovered=elf_result.executables_detected,
            elf_libraries_discovered=elf_result.libraries_detected,
            elf_non_elf_files_skipped=elf_result.non_elf_files_skipped,
            elf_symlinks_skipped=elf_result.symlinks_skipped,
            elf_oversized_files_skipped=elf_result.oversized_files_skipped,
            elf_malformed_files=elf_result.malformed_elf_files,
            elf_unreadable_files=elf_result.unreadable_files,
            elf_unsupported_files=elf_result.unsupported_elf_files,
            extraction_placeholder_entries=elf_result.extraction_placeholder_entries,
            open_read_failures=elf_result.open_read_failures,
            elf_discovery_limit_reached=elf_result.discovery_limit_reached,
            raw_components_discovered=(
                package_component_count
                + known_binary_component_count
                + len(elf_result.components)
            ),
            merged_components=len(merged_components),
            components_with_known_versions=known_versions,
            components_with_unknown_versions=len(merged_components) - known_versions,
            components_with_cpe_candidates=sum(
                bool(component.cpe_candidates) for component in merged_components
            ),
        )
