from pathlib import Path

from app.domain.entities.component import Component
from app.infrastructure.elf.inventory_scanner import (
    ElfInventoryScanner,
    _ElfParseResult,
)


def _root(tmp_path: Path, *names: str) -> Path:
    directory = tmp_path / "bin"
    directory.mkdir()
    for name in names:
        (directory / name).write_bytes(b"\x7fELF")
    return tmp_path


def test_open_failure_is_unreadable_and_is_diagnosed(
    tmp_path: Path, monkeypatch: object
) -> None:
    root = _root(tmp_path, "blocked")

    def _raise_open(self: Path, *args: object, **kwargs: object) -> object:
        raise PermissionError("read denied")

    monkeypatch.setattr(Path, "open", _raise_open)
    result = ElfInventoryScanner().scan(root)

    assert result.unreadable_files == 1
    assert result.malformed_elf_files == 0
    assert result.unreadable_diagnostics[0].exception_type == "PermissionError"
    assert result.unreadable_diagnostics[0].reason == "unreadable_files"


def test_readable_truncated_elf_is_malformed(tmp_path: Path) -> None:
    result = ElfInventoryScanner().scan(_root(tmp_path, "truncated"))

    assert result.malformed_elf_files == 1
    assert result.unreadable_files == 0
    assert result.malformed_diagnostics[0].exception_type == "ELFError"


def test_parser_exception_after_read_is_malformed_and_scan_continues(tmp_path: Path) -> None:
    root = _root(tmp_path, "broken", "good")
    good = Component(name="good", component_type="executable")

    class _Scanner(ElfInventoryScanner):
        def _parse(self, path: Path) -> _ElfParseResult:
            with path.open("rb") as handle:
                handle.read(4)
            if path.name == "broken":
                raise RuntimeError("synthetic parser failure")
            return _ElfParseResult(good)

    result = _Scanner().scan(root)

    assert result.malformed_elf_files == 1
    assert result.malformed_diagnostics[0].exception_type == "RuntimeError"
    assert result.components == (good,)


def test_diagnostic_samples_are_capped_without_stopping_scan(tmp_path: Path) -> None:
    root = _root(tmp_path, "one", "two", "three")

    class _Scanner(ElfInventoryScanner):
        def _parse(self, path: Path) -> _ElfParseResult:
            return _ElfParseResult(
                None,
                "malformed_elf_files",
                self._diagnostic(path, "malformed_elf_files", ValueError("bad ELF")),
            )

    result = _Scanner(max_diagnostics=2).scan(root)

    assert result.malformed_elf_files == 3
    assert len(result.malformed_diagnostics) == 2
    assert result.files_examined == 3


def test_scan_continues_after_each_failure_category(tmp_path: Path) -> None:
    root = _root(tmp_path, "unreadable", "unsupported", "good")
    good = Component(name="good", component_type="executable")

    class _Scanner(ElfInventoryScanner):
        def _parse(self, path: Path) -> _ElfParseResult:
            if path.name == "unreadable":
                return _ElfParseResult(
                    None,
                    "unreadable_files",
                    self._diagnostic(path, "unreadable_files", PermissionError()),
                )
            if path.name == "unsupported":
                return _ElfParseResult(
                    None,
                    "unsupported_elf_files",
                    self._diagnostic(path, "unsupported_elf_files", NotImplementedError()),
                )
            return _ElfParseResult(good)

    result = _Scanner().scan(root)

    assert result.unreadable_files == 1
    assert result.unsupported_elf_files == 1
    assert result.components == (good,)
