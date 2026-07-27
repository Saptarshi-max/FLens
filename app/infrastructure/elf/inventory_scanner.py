import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection, DynamicTag
from elftools.elf.elffile import ELFFile

from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence


@runtime_checkable
class _StringTableLike(Protocol):
    def get_string(self, offset: int) -> str: ...


def _get_dynamic_string_table(section: DynamicSection) -> _StringTableLike | None:
    candidate = getattr(section, "stringtable", None)
    if candidate is None or not callable(getattr(candidate, "get_string", None)):
        return None
    return cast(_StringTableLike, candidate)


@dataclass(frozen=True, slots=True)
class ElfFailureDiagnostic:
    """A bounded, non-sensitive explanation for one failed ELF candidate."""

    path: str
    exception_type: str
    reason: str


@dataclass(frozen=True, slots=True)
class _ElfParseResult:
    component: Component | None
    reason: str | None = None
    diagnostic: ElfFailureDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class ElfScanResult:
    components: tuple[Component, ...]
    files_examined: int = 0
    executables_detected: int = 0
    libraries_detected: int = 0
    non_elf_files_skipped: int = 0
    symlinks_skipped: int = 0
    oversized_files_skipped: int = 0
    malformed_elf_files: int = 0
    unreadable_files: int = 0
    unsupported_elf_files: int = 0
    regular_files: int = 0
    native_symlinks: int = 0
    broken_symlinks: int = 0
    unsupported_filesystem_entries: int = 0
    extraction_placeholder_entries: int = 0
    open_read_failures: int = 0
    discovery_limit_reached: bool = False
    malformed_diagnostics: tuple[ElfFailureDiagnostic, ...] = ()
    unreadable_diagnostics: tuple[ElfFailureDiagnostic, ...] = ()
    unsupported_diagnostics: tuple[ElfFailureDiagnostic, ...] = ()
    entry_diagnostics: tuple[ElfFailureDiagnostic, ...] = ()


class ElfInventoryScanner:
    """Bounded, non-executing ELF inventory for rootfs binary directories."""

    _roots = ("bin", "sbin", "usr/bin", "usr/sbin", "lib", "usr/lib")

    def __init__(
        self,
        max_files: int = 5000,
        max_file_size: int = 64 * 1024 * 1024,
        max_diagnostics: int = 20,
    ) -> None:
        self._max_files = max_files
        self._max_file_size = max_file_size
        self._max_diagnostics = max_diagnostics

    def scan(self, rootfs: Path) -> ElfScanResult:
        found: list[Component] = []
        counts: dict[str, int] = {
            "files_examined": 0,
            "executables_detected": 0,
            "libraries_detected": 0,
            "non_elf_files_skipped": 0,
            "symlinks_skipped": 0,
            "oversized_files_skipped": 0,
            "malformed_elf_files": 0,
            "unreadable_files": 0,
            "unsupported_elf_files": 0,
            "regular_files": 0,
            "native_symlinks": 0,
            "broken_symlinks": 0,
            "unsupported_filesystem_entries": 0,
            "extraction_placeholder_entries": 0,
            "open_read_failures": 0,
        }
        diagnostics: dict[str, list[ElfFailureDiagnostic]] = {
            "malformed_elf_files": [],
            "unreadable_files": [],
            "unsupported_elf_files": [],
            "entry": [],
        }
        applets = self._busybox_applets(rootfs)
        applet_paths: list[Path] = []
        for relative in self._roots:
            for base, _, names in os.walk(rootfs / relative, followlinks=False):
                for name in names:
                    if counts["files_examined"] >= self._max_files:
                        return self._result(found, counts, diagnostics, True)
                    path = Path(base) / name
                    counts["files_examined"] += 1
                    classification, entry_diagnostic = self._classify(path)
                    counts[classification] += 1
                    if classification != "regular_files":
                        if classification == "extraction_placeholder_entries" and name in applets:
                            if len(applet_paths) < 256:
                                applet_paths.append(path)
                        if entry_diagnostic and len(diagnostics["entry"]) < self._max_diagnostics:
                            diagnostics["entry"].append(entry_diagnostic)
                        continue
                    try:
                        outcome = self._parse(path)
                    except Exception as error:
                        outcome = _ElfParseResult(
                            None,
                            diagnostic=self._diagnostic(
                                path, "malformed_elf_files", error
                            ),
                            reason="malformed_elf_files",
                        )
                    if outcome.component is not None:
                        found.append(outcome.component)
                        counter = (
                            "libraries_detected"
                            if outcome.component.component_type == "library"
                            else "executables_detected"
                        )
                        counts[counter] += 1
                    elif outcome.reason is not None:
                        counts[outcome.reason] += 1
                        if outcome.reason == "unreadable_files":
                            counts["open_read_failures"] += 1
                        if outcome.diagnostic is not None:
                            samples = diagnostics.get(outcome.diagnostic.reason)
                            if samples is not None and len(samples) < self._max_diagnostics:
                                samples.append(outcome.diagnostic)
        found.extend(self._applet_evidence(rootfs, applet_paths))
        return self._result(found, counts, diagnostics, False)

    @staticmethod
    def _classify(path: Path) -> tuple[str, ElfFailureDiagnostic | None]:
        try:
            entry = os.lstat(path)
        except OSError as error:
            return "open_read_failures", ElfInventoryScanner._diagnostic(
                path, "other-os-error", error
            )
        if stat.S_ISLNK(entry.st_mode):
            try:
                os.stat(path)
            except FileNotFoundError as error:
                return "broken_symlinks", ElfInventoryScanner._diagnostic(
                    path, "path-not-found", error
                )
            except OSError as error:
                return "native_symlinks", ElfInventoryScanner._diagnostic(
                    path, "other-os-error", error
                )
            return "native_symlinks", None
        attributes = getattr(entry, "st_file_attributes", 0)
        tag = getattr(entry, "st_reparse_tag", 0)
        if attributes & 0x400:
            reason = "invalid-path-or-extraction-representation"
            category = (
                "extraction_placeholder_entries"
                if tag == 0xA000001D
                else "unsupported_filesystem_entries"
            )
            return category, ElfFailureDiagnostic(str(path), "WindowsReparsePoint", reason)
        if stat.S_ISREG(entry.st_mode):
            return "regular_files", None
        return "unsupported_filesystem_entries", ElfFailureDiagnostic(
            str(path), "FilesystemEntry", "unsupported-filesystem-entry"
        )

    @staticmethod
    def _busybox_applets(rootfs: Path) -> set[str]:
        try:
            data = (rootfs / "bin" / "busybox").read_bytes()
        except OSError:
            return set()
        return {
            word.decode("ascii")
            for word in re.findall(rb"\x00([A-Za-z0-9_+.-]{2,})\x00", data)
        }

    @staticmethod
    def _applet_evidence(rootfs: Path, paths: list[Path]) -> list[Component]:
        if not paths:
            return []
        ordered = sorted(paths, key=lambda value: value.name)
        metadata = [("applet_evidence_source", "busybox_binary_strings")]
        metadata.extend(("applet", path.name) for path in ordered)
        metadata.extend(("applet_path", str(path)) for path in ordered)
        return [
            Component(
                name="busybox",
                component_type="executable",
                confidence="MEDIUM",
                evidence=(
                    Evidence(
                        "busybox_applet_strings",
                        str(rootfs / "bin" / "busybox"),
                        f"{len(ordered)} applets",
                    ),
                ),
                metadata=tuple(metadata),
            )
        ]

    @staticmethod
    def _diagnostic(
        path: Path, reason: str, error: BaseException
    ) -> ElfFailureDiagnostic:
        return ElfFailureDiagnostic(str(path), type(error).__name__, reason)

    @staticmethod
    def _result(
        found: list[Component],
        counts: dict[str, int],
        diagnostics: dict[str, list[ElfFailureDiagnostic]],
        discovery_limit_reached: bool,
    ) -> ElfScanResult:
        return ElfScanResult(
            tuple(found),
            files_examined=counts["files_examined"],
            executables_detected=counts["executables_detected"],
            libraries_detected=counts["libraries_detected"],
            non_elf_files_skipped=counts["non_elf_files_skipped"],
            symlinks_skipped=counts["symlinks_skipped"],
            oversized_files_skipped=counts["oversized_files_skipped"],
            malformed_elf_files=counts["malformed_elf_files"],
            unreadable_files=counts["unreadable_files"],
            unsupported_elf_files=counts["unsupported_elf_files"],
            regular_files=counts["regular_files"],
            native_symlinks=counts["native_symlinks"],
            broken_symlinks=counts["broken_symlinks"],
            unsupported_filesystem_entries=counts["unsupported_filesystem_entries"],
            extraction_placeholder_entries=counts["extraction_placeholder_entries"],
            open_read_failures=counts["open_read_failures"],
            discovery_limit_reached=discovery_limit_reached,
            malformed_diagnostics=tuple(diagnostics["malformed_elf_files"]),
            unreadable_diagnostics=tuple(diagnostics["unreadable_files"]),
            unsupported_diagnostics=tuple(diagnostics["unsupported_elf_files"]),
            entry_diagnostics=tuple(diagnostics["entry"]),
        )

    def _parse(self, path: Path) -> _ElfParseResult:
        try:
            if path.is_symlink():
                return _ElfParseResult(None, "symlinks_skipped")
            if path.stat().st_size > self._max_file_size:
                return _ElfParseResult(None, "oversized_files_skipped")
            with path.open("rb") as handle:
                if handle.read(4) != b"\x7fELF":
                    return _ElfParseResult(None, "non_elf_files_skipped")
                handle.seek(0)
                elf = ELFFile(handle)
                dynamic = next(
                    (
                        section
                        for section in elf.iter_sections()
                        if isinstance(section, DynamicSection)
                    ),
                    None,
                )
                tags = tuple(dynamic.iter_tags()) if dynamic is not None else ()
                soname = next(
                    (
                        self._dynamic_string(dynamic, tag)
                        for tag in tags
                        if tag.entry.d_tag == "DT_SONAME"
                    ),
                    None,
                )
                needed = tuple(
                    value
                    for tag in tags
                    if tag.entry.d_tag == "DT_NEEDED"
                    if (value := self._dynamic_string(dynamic, tag)) is not None
                )
                kind = "library" if soname or ".so" in path.name else "executable"
                return _ElfParseResult(
                    Component(
                        name=soname or path.name,
                        component_type=kind,
                        architecture=str(elf["e_machine"]),
                        dependencies=needed,
                        confidence="MEDIUM",
                        evidence=(
                            Evidence(
                                "elf_metadata",
                                str(path),
                                f"{kind}; linked: {', '.join(needed) or 'none'}",
                            ),
                        ),
                    )
                )
        except ELFError as error:
            return _ElfParseResult(
                None,
                "malformed_elf_files",
                self._diagnostic(path, "malformed_elf_files", error),
            )
        except OSError as error:
            return _ElfParseResult(
                None,
                "unreadable_files",
                self._diagnostic(path, "unreadable_files", error),
            )
        except NotImplementedError as error:
            return _ElfParseResult(
                None,
                "unsupported_elf_files",
                self._diagnostic(path, "unsupported_elf_files", error),
            )
        except Exception as error:
            return _ElfParseResult(
                None,
                "malformed_elf_files",
                self._diagnostic(path, "malformed_elf_files", error),
            )

    @staticmethod
    def _dynamic_string(section: DynamicSection | None, tag: DynamicTag) -> str | None:
        """Resolve a dynamic string through the section string table, if structurally valid."""
        if section is None:
            return None
        try:
            offset = tag.entry["d_val"]
            string_table = _get_dynamic_string_table(section)
            if not isinstance(offset, int) or string_table is None:
                return None
            value = string_table.get_string(offset)
            return value if isinstance(value, str) else None
        except (AttributeError, ELFError, KeyError, OSError, TypeError, ValueError):
            return None
