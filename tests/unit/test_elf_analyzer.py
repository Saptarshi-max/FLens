from pathlib import Path

import pytest

from app.infrastructure.elf import elf_analyzer as elf_module
from app.infrastructure.elf.elf_analyzer import ELFAnalyzer


class _FakeELF:
    def __getitem__(self, key: str) -> str:
        if key == "e_machine":
            return "EM_ARM"
        if key == "e_type":
            return "ET_EXEC"
        raise KeyError(key)


def test_analyze_non_elf_returns_none(tmp_path: Path) -> None:
    file_path = tmp_path / "not_elf.bin"
    file_path.write_bytes(b"not an elf")

    analyzer = ELFAnalyzer()

    assert analyzer.analyze(file_path) is None


def test_analyze_elf_infers_component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "binary"
    file_path.write_bytes(b"\x7fELF" + b"x" * 128)

    monkeypatch.setattr(elf_module, "ELFFile", lambda _fh: _FakeELF())
    monkeypatch.setattr(
        ELFAnalyzer,
        "_extract_strings_streaming",
        lambda _self, _path: ("OpenSSL 1.1.1d",),
    )

    analyzer = ELFAnalyzer()
    analysis = analyzer.analyze(file_path)

    assert analysis is not None
    assert analysis.architecture == "EM_ARM"
    assert analysis.inferred_component == "openssl"
