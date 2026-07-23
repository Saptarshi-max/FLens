from pathlib import Path

from app.infrastructure.parsers.filesystem_component_detector import (
    FileSystemComponentDetector,
)
from app.infrastructure.parsers.static_version_resolver import StaticVersionResolver


def test_detect_busybox(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir(parents=True)
    (tmp_path / "bin" / "busybox").write_text("x", encoding="utf-8")

    detector = FileSystemComponentDetector(StaticVersionResolver())
    result = detector.detect(tmp_path)

    assert len(result) == 1
    assert result[0].name == "busybox"


def test_detect_openssl(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir(parents=True)
    (tmp_path / "bin" / "openssl").write_text("x", encoding="utf-8")

    detector = FileSystemComponentDetector(StaticVersionResolver())
    result = detector.detect(tmp_path)

    assert len(result) == 1
    assert result[0].name == "openssl"


def test_detect_multiple_components(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir(parents=True)
    (tmp_path / "bin" / "busybox").write_text("x", encoding="utf-8")
    (tmp_path / "bin" / "openssl").write_text("x", encoding="utf-8")
    (tmp_path / "bin" / "dropbear").write_text("x", encoding="utf-8")

    detector = FileSystemComponentDetector(StaticVersionResolver())
    result = detector.detect(tmp_path)

    names = {c.name for c in result}
    assert names == {"busybox", "openssl", "dropbear"}


def test_detect_empty_filesystem(tmp_path: Path) -> None:
    detector = FileSystemComponentDetector(StaticVersionResolver())

    result = detector.detect(tmp_path)

    assert result == []
