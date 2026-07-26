from dataclasses import dataclass
from pathlib import Path

from app.domain.entities.evidence import Evidence


@dataclass(frozen=True, slots=True)
class PackageRecord:
    name: str
    version: str
    evidence: Evidence


class PackageDatabaseParser:
    """Read installed-package metadata from common embedded Linux root filesystems."""

    _status_paths = (("opkg", "usr/lib/opkg/status"), ("dpkg", "var/lib/dpkg/status"))
    _apk_path = "lib/apk/db/installed"

    def parse(self, rootfs_path: Path) -> tuple[PackageRecord, ...]:
        records: list[PackageRecord] = []
        for format_name, relative_path in self._status_paths:
            path = rootfs_path / relative_path
            if self._is_regular_file(path):
                records.extend(self._parse_debian_control(path, format_name))
        apk_path = rootfs_path / self._apk_path
        if self._is_regular_file(apk_path):
            records.extend(self._parse_apk(apk_path))
        return tuple(records)

    @staticmethod
    def _is_regular_file(path: Path) -> bool:
        try:
            return not path.is_symlink() and path.is_file()
        except OSError:
            return False

    def _parse_debian_control(self, path: Path, format_name: str) -> list[PackageRecord]:
        try:
            paragraphs = path.read_text(encoding="utf-8", errors="replace").split("\n\n")
        except OSError:
            return []
        records: list[PackageRecord] = []
        for paragraph in paragraphs:
            fields = {
                key.strip().lower(): value.strip()
                for line in paragraph.splitlines()
                if ":" in line
                for key, value in [line.split(":", 1)]
            }
            name, version = fields.get("package"), fields.get("version")
            if name and version:
                detail = f"Package: {name}; Version: {version}"
                records.append(
                    PackageRecord(name, version, Evidence(format_name, str(path), detail))
                )
        return records

    def _parse_apk(self, path: Path) -> list[PackageRecord]:
        try:
            paragraphs = path.read_text(encoding="utf-8", errors="replace").split("\n\n")
        except OSError:
            return []
        records: list[PackageRecord] = []
        for paragraph in paragraphs:
            fields = {
                line[:2]: line[2:]
                for line in paragraph.splitlines()
                if len(line) > 2 and line[1] == ":"
            }
            name, version = fields.get("P:"), fields.get("V:")
            if name and version:
                records.append(
                    PackageRecord(
                        name, version, Evidence("apk", str(path), f"P:{name}; V:{version}")
                    )
                )
        return records
