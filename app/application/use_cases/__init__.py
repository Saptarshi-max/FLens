"""Application use cases."""

from .analyze_firmware import AnalyzeFirmwareUseCase, FirmwareAnalysisResult
from .analyze_firmware_intelligence import (
	AnalyzeFirmwareIntelligenceUseCase,
	FirmwareIntelligenceResult,
)
from .generate_sbom import GenerateSBOMResult, GenerateSBOMUseCase
from .scan_firmware import ScanFirmwareUseCase
from .store_scan import StoreScanUseCase

__all__ = [
	"ScanFirmwareUseCase",
	"AnalyzeFirmwareUseCase",
	"FirmwareAnalysisResult",
	"GenerateSBOMUseCase",
	"GenerateSBOMResult",
	"StoreScanUseCase",
	"AnalyzeFirmwareIntelligenceUseCase",
	"FirmwareIntelligenceResult",
]
