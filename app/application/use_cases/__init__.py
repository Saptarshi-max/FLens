"""Application use cases."""

from .analyze_firmware import AnalyzeFirmwareUseCase, FirmwareAnalysisResult
from .scan_firmware import ScanFirmwareUseCase

__all__ = ["ScanFirmwareUseCase", "AnalyzeFirmwareUseCase", "FirmwareAnalysisResult"]
