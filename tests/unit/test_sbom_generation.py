from app.application.use_cases.generate_sbom import GenerateSBOMUseCase
from app.domain.entities.component import Component
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.infrastructure.sbom.json_sbom_generator import JsonSBOMGenerator


def _scan_result() -> ScanResult:
    return ScanResult(
        components=(
            Component(name="openssl", version="1.1.1d"),
            Component(name="busybox", version="1.35.0"),
        ),
        vulnerabilities=(
            Vulnerability(
                cve_id="CVE-2022-0778",
                severity="HIGH",
                description="Infinite loop in BN_mod_sqrt",
            ),
        ),
        risk_score="HIGH",
    )


def test_generate_cyclonedx_and_spdx() -> None:
    use_case = GenerateSBOMUseCase(sbom_generator=JsonSBOMGenerator())

    result = use_case.execute(_scan_result())

    assert result.cyclonedx.format.value == "cyclonedx-json"
    assert result.cyclonedx.content["bomFormat"] == "CycloneDX"
    assert len(result.cyclonedx.content["components"]) == 2

    assert result.spdx.format.value == "spdx-json"
    assert result.spdx.content["spdxVersion"] == "SPDX-2.3"
    assert len(result.spdx.content["packages"]) == 2
