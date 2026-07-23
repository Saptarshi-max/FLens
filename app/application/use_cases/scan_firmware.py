from pathlib import Path

from app.application.services.risk_engine import RiskEngine
from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.component_detector import ComponentDetector
from app.domain.interfaces.vulnerability_provider import VulnerabilityProvider


class ScanFirmwareUseCase:
    """Run a full rootfs scan and produce a domain scan result."""

    def __init__(
        self,
        component_detector: ComponentDetector,
        vulnerability_provider: VulnerabilityProvider,
        risk_engine: RiskEngine,
    ) -> None:
        self._component_detector = component_detector
        self._vulnerability_provider = vulnerability_provider
        self._risk_engine = risk_engine

    def execute(self, rootfs_path: Path) -> ScanResult:
        components = self._component_detector.detect(rootfs_path)
        vulnerabilities = self._vulnerability_provider.find_for_components(components)
        risk_score = self._risk_engine.score(vulnerabilities)

        return ScanResult(
            components=tuple(components),
            vulnerabilities=tuple(vulnerabilities),
            risk_score=risk_score.value,
        )
