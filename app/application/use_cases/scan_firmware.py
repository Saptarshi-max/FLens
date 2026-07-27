from pathlib import Path

from app.application.services.risk_engine import RiskEngine
from app.domain.entities.component import Component
from app.domain.entities.identity_statistics import IdentityStatistics
from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.component_detector import ComponentDetector
from app.domain.interfaces.vulnerability_provider import VulnerabilityProvider
from app.domain.services.cpe_selection import select_cpe_candidates
from app.infrastructure.cpe.component_identity_resolver import ComponentIdentityResolver


class ScanFirmwareUseCase:
    """Run a full rootfs scan and produce a domain scan result."""

    def __init__(
        self,
        component_detector: ComponentDetector,
        vulnerability_provider: VulnerabilityProvider,
        risk_engine: RiskEngine,
        identity_resolver: ComponentIdentityResolver | None = None,
    ) -> None:
        self._component_detector = component_detector
        self._vulnerability_provider = vulnerability_provider
        self._risk_engine = risk_engine
        self._identity_resolver = identity_resolver or ComponentIdentityResolver()

    def execute(self, rootfs_path: Path) -> ScanResult:
        detailed = getattr(self._component_detector, "detect_with_statistics", None)
        inventory = detailed(rootfs_path) if callable(detailed) else None
        components = (
            list(inventory.components)
            if inventory
            else self._component_detector.detect(rootfs_path)
        )
        components = [self._resolve_identity(component) for component in components]
        vulnerabilities = self._vulnerability_provider.find_for_components(components)
        risk_score = self._risk_engine.score(vulnerabilities)

        return ScanResult(
            components=tuple(components),
            vulnerabilities=tuple(vulnerabilities),
            risk_score=risk_score.value,
            inventory_statistics=inventory.statistics if inventory else None,
            inventory_diagnostics=inventory.diagnostics if inventory else (),
            identity_statistics=self._identity_statistics(components),
        )

    @staticmethod
    def _identity_statistics(components: list[Component]) -> IdentityStatistics:
        statuses = {
            name: 0
            for name in (
                "resolved",
                "excluded",
                "ambiguous",
                "unsupported",
                "insufficient_evidence",
            )
        }
        sources = {name: 0 for name in ("governed", "legacy", "none")}
        for component in components:
            identity = component.identity_resolution
            statuses[identity.resolution_status if identity else "insufficient_evidence"] += 1
            sources[select_cpe_candidates(component).source] += 1
        return IdentityStatistics(
            **statuses,
            governed_cpe_components=sources["governed"],
            legacy_cpe_components=sources["legacy"],
            no_cpe_components=sources["none"],
        )

    def _resolve_identity(self, component: Component) -> Component:
        identity = self._identity_resolver.resolve(component)
        resolved_component = Component(
            name=component.name,
            version=component.version,
            evidence=component.evidence,
            confidence=component.confidence,
            cpe=component.cpe,
            cpe_candidates=component.cpe_candidates,
            cpe_confidence=component.cpe_confidence,
            component_type=component.component_type,
            architecture=component.architecture,
            dependencies=component.dependencies,
            metadata=component.metadata,
            identity_resolution=identity,
        )
        selection = select_cpe_candidates(resolved_component)
        return Component(
            name=component.name,
            version=component.version,
            evidence=component.evidence,
            confidence=component.confidence,
            cpe=selection.candidates[0] if selection.candidates else None,
            cpe_candidates=selection.candidates,
            cpe_confidence=(
                identity.confidence if selection.source == "governed" else component.cpe_confidence
            ),
            component_type=component.component_type,
            architecture=component.architecture,
            dependencies=component.dependencies,
            metadata=component.metadata,
            identity_resolution=identity,
            cpe_source=selection.source,
        )
