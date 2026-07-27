from app.domain.entities.component import Component
from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.sbom_generator import SBOMGenerator
from app.domain.sbom.models import SBOMComponent, SBOMDocument, SBOMFormat
from app.domain.services.cpe_selection import select_cpe_candidates


class JsonSBOMGenerator(SBOMGenerator):
    """Generate CycloneDX and SPDX JSON SBOM documents.

    Firmware-observed component names and versions are authoritative. Selected
    CPEs may enrich those records, but canonical resolver identity is not yet
    serialised because neither output currently has a suitable non-speculative
    field for it.
    """

    def generate(self, scan_result: ScanResult, format: SBOMFormat) -> SBOMDocument:
        observed_components = tuple(
            sorted(
                scan_result.components,
                key=lambda component: (component.name, component.version),
            )
        )
        components = tuple(
            SBOMComponent(name=component.name, version=component.version)
            for component in observed_components
        )

        if format == SBOMFormat.CYCLONEDX_JSON:
            return SBOMDocument(
                format=format,
                components=components,
                content={
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "components": [
                        self._cyclonedx_component(component)
                        for component in observed_components
                    ],
                },
            )

        return SBOMDocument(
            format=SBOMFormat.SPDX_JSON,
            components=components,
            content={
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "flens-sbom",
                "packages": [self._spdx_package(component) for component in observed_components],
            },
        )

    @staticmethod
    def _cyclonedx_component(component: Component) -> dict[str, str]:
        content = {
            "type": "library",
            "name": component.name,
            "version": component.version,
        }
        candidates = select_cpe_candidates(component).candidates
        # CycloneDX exposes one cpe property; shared selection is sorted, so
        # the first candidate is a deterministic, schema-valid choice.
        if candidates:
            content["cpe"] = candidates[0]
        return content

    @staticmethod
    def _spdx_package(component: Component) -> dict[str, object]:
        content: dict[str, object] = {
            "name": component.name,
            "SPDXID": f"SPDXRef-Package-{component.name}",
            "versionInfo": component.version,
            "downloadLocation": "NOASSERTION",
        }
        candidates = select_cpe_candidates(component).candidates
        if candidates:
            content["externalRefs"] = [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": candidate,
                }
                for candidate in candidates
            ]
        return content
