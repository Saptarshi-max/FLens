from pathlib import Path

import pytest

from app.domain.entities.component import Component
from app.infrastructure.elf.inventory_scanner import ElfInventoryScanner, _ElfParseResult


class _Scanner(ElfInventoryScanner):
    def __init__(self, outcomes: dict[str, _ElfParseResult]) -> None:
        super().__init__()
        self.outcomes = outcomes

    def _parse(self, path: Path) -> _ElfParseResult:
        return self.outcomes[path.name]


def _root(tmp_path: Path, *names: str) -> Path:
    directory = tmp_path / "bin"
    directory.mkdir()
    for name in names:
        (directory / name).write_bytes(b"x")
    return tmp_path


@pytest.mark.parametrize(
    "reason",
    ["non_elf_files_skipped", "symlinks_skipped", "oversized_files_skipped", "malformed_elf_files"],
)
def test_skip_counters(tmp_path: Path, reason: str) -> None:
    root = _root(tmp_path, "item")
    result = _Scanner({"item": _ElfParseResult(None, reason)}).scan(root)
    assert result.files_examined == 1
    assert getattr(result, reason) == 1
    assert result.components == ()


def test_executable_and_library_counters_only_return_successes(tmp_path: Path) -> None:
    root = _root(tmp_path, "app", "libx")
    app = Component(name="app", component_type="executable")
    library = Component(name="libx.so.1", component_type="library")
    result = _Scanner(
        {"app": _ElfParseResult(app), "libx": _ElfParseResult(library)}
    ).scan(root)
    assert result.files_examined == 2
    assert result.executables_detected == 1
    assert result.libraries_detected == 1
    assert result.components == (app, library)


def test_discovery_limit_is_reported(tmp_path: Path) -> None:
    root = _root(tmp_path, "one", "two")
    scanner = _Scanner(
        {
            "one": _ElfParseResult(None, "non_elf_files_skipped"),
            "two": _ElfParseResult(None, "non_elf_files_skipped"),
        }
    )
    scanner._max_files = 1
    result = scanner.scan(root)
    assert result.discovery_limit_reached is True
    assert result.files_examined == 1


def test_parser_exception_is_non_fatal(tmp_path: Path) -> None:
    root = _root(tmp_path, "broken", "good")
    good = Component(name="good", component_type="executable")

    class _FailingScanner(_Scanner):
        def _parse(self, path: Path) -> _ElfParseResult:
            if path.name == "broken":
                raise RuntimeError("synthetic parser failure")
            return _ElfParseResult(good)

    result = _FailingScanner({}).scan(root)
    assert result.malformed_elf_files == 1
    assert result.components == (good,)


@pytest.mark.skipif(
    __import__("sys").platform == "win32",
    reason="Windows ACL behaviour does not reliably deny the owning test process read access.",
)
def test_unreadable_file_counter_is_platform_specific() -> None:
    pytest.skip("Permission-denial fixture is intentionally deferred on this platform.")
