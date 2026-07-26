import os
from pathlib import Path

from app.domain.entities.component import Component
from app.domain.interfaces.component_detector import ComponentDetector
from app.domain.interfaces.version_resolver import VersionResolver
from app.infrastructure.cpe.resolver import CpeResolver
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
        self._cpe_resolver = CpeResolver()
        self._supported_binaries = {"busybox", "openssl", "dropbear"}

    def detect(self, rootfs_path: Path) -> list[Component]:
        if not rootfs_path.exists() or not rootfs_path.is_dir():
            return []

        discovered: dict[str, list[Path]] = {}
        for directory, _, filenames in os.walk(rootfs_path, followlinks=False):
            for filename in filenames:
                file_path = Path(directory) / filename
                try:
                    if file_path.is_symlink() or not file_path.is_file():
                        continue
                except OSError:
                    continue
                binary_name = file_path.name.lower()
                if binary_name in self._supported_binaries:
                    discovered.setdefault(binary_name, []).append(file_path)
                    continue

                if self._elf_analyzer is None:
                    continue

                analysis = self._elf_analyzer.analyze(file_path)
                if analysis is not None and analysis.inferred_component in self._supported_binaries:
                    discovered.setdefault(analysis.inferred_component, []).append(file_path)

        return [
            self._cpe_resolver.resolve(
                Component(
                    name=name,
                    version=resolution.version,
                    evidence=resolution.evidence,
                    confidence=resolution.confidence,
                )
            )
            for name, paths in sorted(discovered.items())
            for resolution in [self._version_resolver.resolve(name, rootfs_path, tuple(paths))]
        ]
