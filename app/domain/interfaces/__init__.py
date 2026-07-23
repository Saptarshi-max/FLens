"""Ports used by the application layer."""

from .component_detector import ComponentDetector
from .firmware_extractor import FirmwareExtractor
from .future_interfaces import (
    CVEFeedProvider,
    FirmwareComparator,
    SBOMGenerator,
    SecretScanner,
)
from .report_generator import ReportGenerator
from .version_resolver import VersionResolver
from .vulnerability_provider import VulnerabilityProvider

__all__ = [
    "ComponentDetector",
    "FirmwareExtractor",
    "VersionResolver",
    "VulnerabilityProvider",
    "ReportGenerator",
    "SBOMGenerator",
    "SecretScanner",
    "FirmwareComparator",
    "CVEFeedProvider",
]
