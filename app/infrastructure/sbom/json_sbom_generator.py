from app.domain.entities.scan_result import ScanResult
from app.domain.interfaces.sbom_generator import SBOMGenerator
from app.domain.sbom.models import SBOMComponent, SBOMDocument, SBOMFormat


class JsonSBOMGenerator(SBOMGenerator):
    """Generate CycloneDX and SPDX JSON SBOM documents."""

    def generate(self, scan_result: ScanResult, format: SBOMFormat) -> SBOMDocument:
        components = tuple(
            SBOMComponent(name=component.name, version=component.version)
            for component in scan_result.components
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
                        {
                            "type": "library",
                            "name": component.name,
                            "version": component.version,
                        }
                        for component in components
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
                "packages": [
                    {
                        "name": component.name,
                        "SPDXID": f"SPDXRef-Package-{component.name}",
                        "versionInfo": component.version,
                        "downloadLocation": "NOASSERTION",
                    }
                    for component in components
                ],
            },
        )
