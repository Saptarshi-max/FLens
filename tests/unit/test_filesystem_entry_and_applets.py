import os
import stat
from pathlib import Path
from types import SimpleNamespace

from app.infrastructure.elf.inventory_scanner import ElfInventoryScanner
from app.infrastructure.inventory.inventory_merger import InventoryMerger


def test_entry_classification_uses_metadata_not_error_text(
    monkeypatch: object, tmp_path: Path
) -> None:
    path = tmp_path / "ash"
    placeholder = SimpleNamespace(
        st_mode=stat.S_IFREG, st_file_attributes=0x400, st_reparse_tag=0xA000001D
    )
    monkeypatch.setattr(os, "lstat", lambda _: placeholder)
    category, diagnostic = ElfInventoryScanner._classify(path)
    assert category == "extraction_placeholder_entries"
    assert diagnostic is not None
    assert diagnostic.reason == "invalid-path-or-extraction-representation"


def test_native_and_broken_symlinks_are_classified(monkeypatch: object, tmp_path: Path) -> None:
    path = tmp_path / "link"
    monkeypatch.setattr(os, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFLNK))
    monkeypatch.setattr(os, "stat", lambda _: SimpleNamespace())
    assert ElfInventoryScanner._classify(path)[0] == "native_symlinks"
    monkeypatch.setattr(os, "stat", lambda _: (_ for _ in ()).throw(FileNotFoundError()))
    assert ElfInventoryScanner._classify(path)[0] == "broken_symlinks"


def test_applet_evidence_deduplicates_and_survives_merge(tmp_path: Path) -> None:
    paths = [tmp_path / "cat", tmp_path / "ash", tmp_path / "cat"]
    applet = ElfInventoryScanner._applet_evidence(tmp_path, paths)[0]
    merged = InventoryMerger().merge([applet, applet])
    assert len(merged) == 1
    assert {value for key, value in merged[0].metadata if key == "applet"} == {"ash", "cat"}
    assert ("applet_evidence_source", "busybox_binary_strings") in merged[0].metadata
