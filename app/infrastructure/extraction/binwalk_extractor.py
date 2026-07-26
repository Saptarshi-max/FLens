import logging
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from app.domain.entities.extraction_result import ExtractionResult
from app.domain.interfaces.firmware_extractor import FirmwareExtractor
from app.infrastructure.extraction.errors import ExtractionError
from app.infrastructure.extraction.filesystem_detector import FilesystemDetector
from app.infrastructure.extraction.squashfs_strategy import SquashfsStrategy

logger = logging.getLogger(__name__)

RunCommand = Callable[[list[str]], subprocess.CompletedProcess[str]]


class BinwalkExtractor(FirmwareExtractor):
    """Firmware extraction backend powered by binwalk."""

    _supported_suffixes = {".bin", ".img", ".trx"}

    def __init__(
        self,
        filesystem_detector: FilesystemDetector | None = None,
        run_command: RunCommand | None = None,
        work_dir: Path | None = None,
        squashfs_strategy: SquashfsStrategy | None = None,
    ) -> None:
        self._filesystem_detector = filesystem_detector or FilesystemDetector()
        self._run_command = run_command or self._default_run_command
        self._work_dir = work_dir
        self._squashfs_strategy = squashfs_strategy or SquashfsStrategy()

    def extract(self, firmware_path: Path) -> ExtractionResult:
        self._validate_input(firmware_path)

        if shutil.which("binwalk") is None:
            raise ExtractionError("Missing binwalk installation.")

        output_dir = self._prepare_output_directory(firmware_path)
        command = [
            "binwalk",
            "--extract",
            # Debian's binwalk refuses to run its extraction helpers as root
            # unless this is explicitly acknowledged. The FLENS Docker image
            # intentionally runs the CLI as root, so pass the user explicitly.
            "--run-as=root",
            "--directory",
            str(output_dir),
            str(firmware_path),
        ]

        logger.info("Starting firmware extraction")
        try:
            completed = self._run_command(command)
        except FileNotFoundError as exc:
            raise ExtractionError(
                "Binwalk is present on PATH but could not be launched. "
                "Verify the binwalk installation and its Python/runtime dependencies."
            ) from exc
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "No error details provided by binwalk."
            raise ExtractionError(f"Binwalk extraction failed. {stderr}")

        root_search = self._locate_extracted_root(output_dir)
        rootfs_path = self._filesystem_detector.find_rootfs(root_search)
        legacy_metadata: dict[str, str] = {}
        if rootfs_path is None:
            offset, version = self._squashfs_details(completed.stdout)
            if offset is not None:
                legacy = self._squashfs_strategy.extract(firmware_path, offset, output_dir)
                rootfs_path = legacy.rootfs_path
                legacy_metadata = {
                    "extractor": legacy.extractor,
                    "squashfs_offset": f"0x{offset:X}",
                    "squashfs_version": version or "Unknown",
                    "warnings": "; ".join(legacy.warnings),
                }
        if rootfs_path is None:
            raise ExtractionError("Empty extraction result.")

        filesystem_type = self._filesystem_detector.detect_filesystem_type(root_search)
        architecture = self._filesystem_detector.detect_architecture(root_search)

        logger.info("Detected %s filesystem", filesystem_type)
        return ExtractionResult(
            firmware_path=firmware_path,
            extracted_path=rootfs_path,
            filesystem_type=filesystem_type,
            architecture=architecture,
            metadata={
                "backend": "binwalk",
                "command": " ".join(command),
                "stdout": completed.stdout.strip(),
                **legacy_metadata,
            },
        )

    def _prepare_output_directory(self, firmware_path: Path) -> Path:
        if self._work_dir is None:
            return Path(tempfile.mkdtemp(prefix="flens_extract_"))

        self._work_dir.mkdir(parents=True, exist_ok=True)
        output_dir = self._work_dir / f"{firmware_path.stem}_extract"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    @staticmethod
    def _locate_extracted_root(output_dir: Path) -> Path:
        extracted_dirs = [
            p
            for p in output_dir.iterdir()
            if p.is_dir() and (p.name.endswith(".extracted") or p.name.endswith("_extracted"))
        ]
        if extracted_dirs:
            return extracted_dirs[0]
        return output_dir

    def _validate_input(self, firmware_path: Path) -> None:
        if not firmware_path.exists() or not firmware_path.is_file():
            raise ExtractionError("Invalid firmware file.")

        suffix = firmware_path.suffix.lower()
        if suffix not in self._supported_suffixes:
            supported = ", ".join(sorted(self._supported_suffixes))
            raise ExtractionError(f"Unsupported format: {suffix}. Supported formats: {supported}")

    @staticmethod
    def _squashfs_details(stdout: str) -> tuple[int | None, str | None]:
        match = re.search(
            r"^(\d+).*Squashfs filesystem.*version\s+([\d.]+)", stdout, re.MULTILINE | re.IGNORECASE
        )
        return (int(match.group(1)), match.group(2)) if match else (None, None)

    @staticmethod
    def _default_run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
