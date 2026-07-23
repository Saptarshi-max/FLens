"""Domain entities."""

from .component import Component
from .extraction_result import ExtractionResult
from .scan_result import ScanResult
from .vulnerability import Vulnerability

__all__ = ["Component", "Vulnerability", "ScanResult", "ExtractionResult"]
