"""Compatibility module for Phase 3 use case location."""

from app.application.use_cases.analyze_firmware import (
    AnalyzeFirmwareUseCase,
    FirmwareAnalysisResult,
)

__all__ = ["AnalyzeFirmwareUseCase", "FirmwareAnalysisResult"]
