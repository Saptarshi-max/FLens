from pathlib import Path

from app.domain.entities.component import Component
from app.domain.interfaces.component_detector import ComponentDetector
from app.domain.interfaces.version_resolver import VersionResolver


class FileSystemComponentDetector(ComponentDetector):
    """Detect known components by filename within extracted rootfs."""

    def __init__(self, version_resolver: VersionResolver) -> None:
        self._version_resolver = version_resolver
        self._supported_binaries = {"busybox", "openssl", "dropbear"}

    def detect(self, rootfs_path: Path) -> list[Component]:
        if not rootfs_path.exists() or not rootfs_path.is_dir():
            return []

        discovered: set[str] = set()
        for file_path in rootfs_path.rglob("*"):
            if not file_path.is_file():
                continue
            binary_name = file_path.name.lower()
            if binary_name in self._supported_binaries:
                discovered.add(binary_name)

        return [
            Component(name=name, version=self._version_resolver.resolve(name))
            for name in sorted(discovered)
        ]
