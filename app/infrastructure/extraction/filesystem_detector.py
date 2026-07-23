from pathlib import Path


class FilesystemDetector:
    """Heuristics for identifying extracted rootfs and metadata."""

    _filesystem_markers: dict[str, str] = {
        "squashfs": "SquashFS",
        "ubifs": "UBIFS",
        "ubi": "UBI",
        "jffs2": "JFFS2",
    }

    _architecture_markers: dict[str, str] = {
        "aarch64": "ARM64",
        "arm": "ARM",
        "mips": "MIPS",
        "x86_64": "x86_64",
    }

    def find_rootfs(self, extracted_root: Path) -> Path | None:
        if self._looks_like_rootfs(extracted_root):
            return extracted_root

        for directory in sorted((p for p in extracted_root.rglob("*") if p.is_dir()), key=str):
            if self._looks_like_rootfs(directory):
                return directory

        return None

    def detect_filesystem_type(self, extracted_root: Path) -> str:
        for path in extracted_root.rglob("*"):
            if not path.is_file():
                continue
            lower_name = path.name.lower()
            for marker, label in self._filesystem_markers.items():
                if marker in lower_name:
                    return label
        return "Unknown"

    def detect_architecture(self, extracted_root: Path) -> str:
        for path in extracted_root.rglob("*"):
            lower_name = path.name.lower()
            for marker, label in self._architecture_markers.items():
                if marker in lower_name:
                    return label
        return "Unknown"

    @staticmethod
    def _looks_like_rootfs(directory: Path) -> bool:
        return (directory / "bin").exists() and (directory / "usr").exists()
