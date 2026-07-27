"""Deterministic, evidence-preserving component inventory merging."""

from collections.abc import Iterable

from app.domain.entities.component import Component
from app.domain.entities.evidence import Evidence


class InventoryMerger:
    """Merge only components with an exact, normalised inventory identity.

    Application and package names are compared case-insensitively. Libraries use
    their exact lower-cased SONAME or filename, including any ABI suffix. Thus
    ``libssl.so.1.1`` is stable across paths and case variations, while it remains
    distinct from ``libssl.so.3`` to retain ABI-specific matching precision.
    """

    _UNKNOWN = "Unknown"

    def merge(self, components: Iterable[Component]) -> list[Component]:
        groups: dict[str, list[Component]] = {}
        for component in components:
            groups.setdefault(self.identity(component), []).append(component)
        return [self._merge_group(groups[identity]) for identity in sorted(groups)]

    @classmethod
    def identity(cls, component: Component) -> str:
        """Return the exact merge identity without fuzzy or prefix matching."""
        name = component.name.replace("\\", "/").rsplit("/", maxsplit=1)[-1].lower()
        if component.component_type == "library" or ".so" in name:
            return f"library:{name}"
        return f"component:{name}"

    def _merge_group(self, components: list[Component]) -> Component:
        ordered = sorted(components, key=self._component_key)
        representative = ordered[0]
        selected = min(ordered, key=self._version_key)
        observed_versions = sorted(
            {component.version for component in ordered if component.version != self._UNKNOWN}
        )
        return Component(
            name=representative.name,
            version=selected.version if observed_versions else self._UNKNOWN,
            evidence=self._evidence(ordered),
            confidence=selected.confidence if observed_versions else representative.confidence,
            cpe=self._first_cpe(ordered),
            cpe_candidates=tuple(
                sorted(
                    {
                        candidate
                        for component in ordered
                        for candidate in component.cpe_candidates
                    }
                )
            ),
            cpe_confidence=self._first_cpe_confidence(ordered),
            component_type=representative.component_type,
            architecture=self._architecture(ordered),
            dependencies=tuple(
                sorted(
                    {
                        dependency
                        for component in ordered
                        for dependency in component.dependencies
                    }
                )
            ),
            metadata=self._metadata(ordered, observed_versions),
        )

    @staticmethod
    def _component_key(component: Component) -> tuple[int, str, str]:
        return (
            0 if component.component_type == "package" else 1,
            component.name.lower(),
            component.component_type,
        )

    def _version_key(self, component: Component) -> tuple[int, str, str, str]:
        if component.version == self._UNKNOWN:
            return (3, "", "", "")
        source_rank = 0 if component.component_type == "package" else 1
        evidence_sources = ",".join(sorted(evidence.source for evidence in component.evidence))
        return (source_rank, component.version, evidence_sources, component.name.lower())

    @staticmethod
    def _evidence(components: list[Component]) -> tuple[Evidence, ...]:
        return tuple(
            sorted(
                {evidence for component in components for evidence in component.evidence},
                key=lambda evidence: (evidence.source, evidence.path, evidence.detail),
            )
        )

    @staticmethod
    def _first_cpe(components: list[Component]) -> str | None:
        for component in components:
            if component.cpe:
                return component.cpe
        return None

    @staticmethod
    def _first_cpe_confidence(components: list[Component]) -> str:
        for component in components:
            if component.cpe_confidence != "LOW":
                return component.cpe_confidence
        return "LOW"

    def _architecture(self, components: list[Component]) -> str:
        architectures = sorted(
            {
                component.architecture
                for component in components
                if component.architecture != self._UNKNOWN
            }
        )
        return architectures[0] if architectures else self._UNKNOWN

    @staticmethod
    def _metadata(
        components: list[Component], observed_versions: list[str]
    ) -> tuple[tuple[str, str], ...]:
        values = {item for component in components for item in component.metadata}
        values.update(("observed_version", version) for version in observed_versions)
        architectures = {
            component.architecture
            for component in components
            if component.architecture != "Unknown"
        }
        values.update(("observed_architecture", value) for value in architectures)
        return tuple(sorted(values))
