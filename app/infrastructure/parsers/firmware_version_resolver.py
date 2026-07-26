import re
from pathlib import Path

from app.domain.entities.evidence import Evidence
from app.domain.interfaces.version_resolver import VersionResolution, VersionResolver
from app.infrastructure.elf.elf_analyzer import ELFAnalyzer
from app.infrastructure.parsers.package_database import PackageDatabaseParser


class FirmwareVersionResolver(VersionResolver):
    """Resolve versions from package metadata and binary version banners only."""

    _patterns = {
        "busybox": re.compile(r"BusyBox\s+(?:v)?([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE),
        "openssl": re.compile(r"OpenSSL\s+([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE),
        "dropbear": re.compile(
            r"Dropbear(?:\s+sshd)?(?:\s+v|_)([0-9][A-Za-z0-9._+-]*)", re.IGNORECASE
        ),
    }

    def __init__(self, package_parser: PackageDatabaseParser | None = None) -> None:
        self._package_parser = package_parser or PackageDatabaseParser()
        self._elf_analyzer = ELFAnalyzer()

    def resolve(
        self, component_name: str, rootfs_path: Path, binary_paths: tuple[Path, ...]
    ) -> VersionResolution:
        normalized = component_name.lower()
        for package in self._package_parser.parse(rootfs_path):
            if self._package_matches(normalized, package.name):
                return VersionResolution(package.version, (package.evidence,), "HIGH")
        for binary_path in binary_paths:
            version = self._version_from_banner(normalized, binary_path)
            if version is not None:
                return VersionResolution(
                    version, (Evidence("binary_banner", str(binary_path), version),), "MEDIUM"
                )
        elf_evidence = tuple(
            Evidence(
                "elf_metadata", str(path), f"ELF {analysis.architecture} {analysis.binary_type}"
            )
            for path in binary_paths
            if (analysis := self._elf_analyzer.analyze(path)) is not None
        )
        return VersionResolution("Unknown", elf_evidence, "LOW")

    @staticmethod
    def _package_matches(component_name: str, package_name: str) -> bool:
        normalized = package_name.lower()
        return (
            normalized == component_name
            or normalized.startswith(f"{component_name}-")
            or component_name in normalized
        )

    def _version_from_banner(self, component_name: str, path: Path) -> str | None:
        pattern = self._patterns.get(component_name)
        if pattern is None:
            return None
        try:
            text = path.read_bytes()[: 4 * 1024 * 1024].decode("latin-1", errors="ignore")
        except OSError:
            return None
        match = pattern.search(text)
        return match.group(1) if match else None
