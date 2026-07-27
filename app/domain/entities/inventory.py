"""Typed inventory results and accounting for component discovery."""

from dataclasses import dataclass

from app.domain.entities.component import Component


@dataclass(frozen=True, slots=True)
class InventoryStatistics:
    """Counts describing the actual source outputs used to build an inventory."""

    package_records_discovered: int = 0
    package_components_discovered: int = 0
    known_binary_components_discovered: int = 0
    elf_files_examined: int = 0
    elf_executables_discovered: int = 0
    elf_libraries_discovered: int = 0
    elf_non_elf_files_skipped: int = 0
    elf_symlinks_skipped: int = 0
    elf_oversized_files_skipped: int = 0
    elf_malformed_files: int = 0
    elf_unreadable_files: int = 0
    elf_unsupported_files: int = 0
    extraction_placeholder_entries: int = 0
    open_read_failures: int = 0
    elf_discovery_limit_reached: bool = False
    raw_components_discovered: int = 0
    merged_components: int = 0
    components_with_known_versions: int = 0
    components_with_unknown_versions: int = 0
    components_with_cpe_candidates: int = 0


@dataclass(frozen=True, slots=True)
class InventoryResult:
    """The final inventory alongside immutable discovery accounting."""

    components: tuple[Component, ...]
    statistics: InventoryStatistics
    diagnostics: tuple[tuple[str, str, str], ...] = ()
