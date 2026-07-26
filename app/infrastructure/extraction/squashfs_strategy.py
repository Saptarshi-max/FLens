import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.infrastructure.extraction.errors import ExtractionError


@dataclass(frozen=True, slots=True)
class SquashfsExtraction:
    rootfs_path: Path
    extractor: str
    offset: int
    warnings: tuple[str, ...]


class SquashfsStrategy:
    """Carve a detected SquashFS payload and explicitly try safe extractors."""

    _root_markers = {"bin", "sbin", "etc", "lib", "usr"}

    def __init__(self, timeout_seconds: int = 120) -> None:
        self._timeout_seconds = timeout_seconds

    def extract(self, firmware: Path, offset: int, output_dir: Path) -> SquashfsExtraction:
        size = firmware.stat().st_size
        if offset < 0 or offset >= size:
            raise ExtractionError(f"Invalid SquashFS offset 0x{offset:X} for firmware size {size}.")
        payload = output_dir / "squashfs-payload.bin"
        output_dir.mkdir(parents=True, exist_ok=True)
        with firmware.open("rb") as source, payload.open("wb") as target:
            source.seek(offset)
            shutil.copyfileobj(source, target, length=1024 * 1024)
        warnings: list[str] = []
        for extractor in ("unsquashfs", "sasquatch"):
            destination = output_dir / f"{extractor}-root"
            result = self._run(extractor, payload, destination)
            if result is None:
                warnings.append(f"{extractor} unavailable or timed out")
                continue
            if result.returncode != 0:
                warnings.append(f"{extractor} failed: {result.stderr.strip()}")
                continue
            if self._meaningful(destination):
                return SquashfsExtraction(destination, extractor, offset, tuple(warnings))
            warnings.append(f"{extractor} produced no meaningful filesystem entries")
        raise ExtractionError(
            f"Legacy SquashFS detected at offset 0x{offset:X}. " + "; ".join(warnings)
        )

    def _run(
        self, extractor: str, payload: Path, destination: Path
    ) -> subprocess.CompletedProcess[str] | None:
        if shutil.which(extractor) is None:
            return None
        try:
            return subprocess.run(
                [extractor, "-d", str(destination), str(payload)],
                capture_output=True,
                text=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

    def _meaningful(self, directory: Path) -> bool:
        try:
            return directory.is_dir() and any(
                (directory / marker).exists() for marker in self._root_markers
            )
        except OSError:
            return False
