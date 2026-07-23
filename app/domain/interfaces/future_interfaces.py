from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.scan_result import ScanResult


class SBOMGenerator(ABC):
    """Generate software bill of materials from scan output."""

    @abstractmethod
    def generate_sbom(self, scan_result: ScanResult, output_dir: Path) -> Path:
        """Generate SBOM artifact and return its path."""


class SecretScanner(ABC):
    """Scan extracted firmware for potential secrets."""

    @abstractmethod
    def scan_secrets(self, rootfs_path: Path) -> list[str]:
        """Return a list of secret findings."""


class FirmwareComparator(ABC):
    """Compare two firmware scans and summarize differences."""

    @abstractmethod
    def compare(self, baseline: ScanResult, candidate: ScanResult) -> dict[str, list[str]]:
        """Return a structured diff for components and vulnerabilities."""


class CVEFeedProvider(ABC):
    """Refresh or fetch CVE data from external feeds."""

    @abstractmethod
    def refresh(self) -> None:
        """Refresh CVE data source."""
