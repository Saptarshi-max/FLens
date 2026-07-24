from pathlib import Path

from app.domain.entities.component import Component
from app.domain.interfaces.component_detector import ComponentDetector
from app.domain.interfaces.version_resolver import VersionResolver
from app.infrastructure.elf.elf_analyzer import ELFAnalyzer


class FileSystemComponentDetector(ComponentDetector):
    """Detect known components by filename within extracted rootfs."""

    def __init__(
        self,
        version_resolver: VersionResolver,
        elf_analyzer: ELFAnalyzer | None = None,
    ) -> None:
        self._version_resolver = version_resolver
        self._elf_analyzer = elf_analyzer
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
                continue

            if self._elf_analyzer is None:
                continue

            analysis = self._elf_analyzer.analyze(file_path)
            if analysis is not None and analysis.inferred_component is not None:
                if analysis.inferred_component in self._supported_binaries:
                    discovered.add(analysis.inferred_component)

        return [
            Component(name=name, version=self._version_resolver.resolve(name))
            for name in sorted(discovered)
        ]
