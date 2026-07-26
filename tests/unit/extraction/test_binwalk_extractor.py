import subprocess
from pathlib import Path

import pytest

from app.infrastructure.extraction.binwalk_extractor import BinwalkExtractor
from app.infrastructure.extraction.errors import ExtractionError

BINWALK_WHICH_TARGET = "app.infrastructure.extraction.binwalk_extractor.shutil.which"


def _mock_completed(
    returncode: int,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["binwalk"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_binwalk_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"test")

    monkeypatch.setattr(BINWALK_WHICH_TARGET, lambda _: "binwalk")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        out_dir = Path(command[command.index("--directory") + 1])
        rootfs = out_dir / "firmware.bin.extracted" / "rootfs"
        (rootfs / "bin").mkdir(parents=True)
        (rootfs / "usr").mkdir(parents=True)
        (rootfs / "squashfs_marker.txt").write_text("x", encoding="utf-8")
        return _mock_completed(returncode=0, stdout="success")

    extractor = BinwalkExtractor(run_command=fake_run, work_dir=tmp_path / "work")

    result = extractor.extract(firmware)

    assert result.filesystem_type == "SquashFS"
    assert result.extracted_path.name == "rootfs"
    assert "--run-as=root" in result.metadata["command"]


def test_binwalk_extraction_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"test")

    monkeypatch.setattr(BINWALK_WHICH_TARGET, lambda _: "binwalk")

    def fake_run(_command: list[str]) -> subprocess.CompletedProcess[str]:
        return _mock_completed(returncode=1, stderr="boom")

    extractor = BinwalkExtractor(run_command=fake_run, work_dir=tmp_path / "work")

    with pytest.raises(ExtractionError, match="Binwalk extraction failed"):
        extractor.extract(firmware)


def test_binwalk_invalid_input_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing_firmware = tmp_path / "missing.bin"
    monkeypatch.setattr(BINWALK_WHICH_TARGET, lambda _: "binwalk")
    extractor = BinwalkExtractor(work_dir=tmp_path / "work")

    with pytest.raises(ExtractionError, match="Invalid firmware file"):
        extractor.extract(missing_firmware)


def test_binwalk_missing_installation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"test")

    monkeypatch.setattr(BINWALK_WHICH_TARGET, lambda _: None)
    extractor = BinwalkExtractor(work_dir=tmp_path / "work")

    with pytest.raises(ExtractionError, match="Missing binwalk installation"):
        extractor.extract(firmware)


def test_binwalk_launch_failure_is_reported_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"test")
    monkeypatch.setattr(BINWALK_WHICH_TARGET, lambda _: "binwalk")

    def missing_command(_: list[str]) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError()

    extractor = BinwalkExtractor(run_command=missing_command, work_dir=tmp_path / "work")

    with pytest.raises(ExtractionError, match="could not be launched"):
        extractor.extract(firmware)


def test_binwalk_unsupported_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    firmware = tmp_path / "firmware.zip"
    firmware.write_bytes(b"test")

    monkeypatch.setattr(BINWALK_WHICH_TARGET, lambda _: "binwalk")
    extractor = BinwalkExtractor(work_dir=tmp_path / "work")

    with pytest.raises(ExtractionError, match="Unsupported format"):
        extractor.extract(firmware)
