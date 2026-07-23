from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.scan_result import ScanResult


class ReportGenerator(ABC):
    """Generate output reports from scan results."""

    @abstractmethod
    def generate(self, scan_result: ScanResult, output_path: Path) -> Path:
        """Generate a report and return the written file path."""
