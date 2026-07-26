"""Ports used by the application layer."""

from .component_detector import ComponentDetector
from .firmware_extractor import FirmwareExtractor
from .firmware_metadata_extractor import FirmwareMetadataExtractor
from .future_interfaces import (
    CVEFeedProvider,
    FirmwareComparator,
    SecretScanner,
)
from .report_generator import ReportGenerator
from .sbom_generator import SBOMGenerator
from .scan_repository import ScanRepository
from .version_resolver import VersionResolution, VersionResolver
from .vulnerability_provider import VulnerabilityProvider

__all__ = [
    "ComponentDetector",
    "FirmwareExtractor",
    "FirmwareMetadataExtractor",
    "VersionResolver",
    "VersionResolution",
    "VulnerabilityProvider",
    "ReportGenerator",
    "ScanRepository",
    "SBOMGenerator",
    "SecretScanner",
    "FirmwareComparator",
    "CVEFeedProvider",
]
