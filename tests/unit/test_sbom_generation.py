from app.application.use_cases.generate_sbom import GenerateSBOMUseCase
from app.domain.entities.component import Component
from app.domain.entities.identity_resolution import IdentityResolution
from app.domain.entities.scan_result import ScanResult
from app.domain.entities.vulnerability import Vulnerability
from app.infrastructure.sbom.json_sbom_generator import JsonSBOMGenerator


def _identity(
    status: str,
    cpes: tuple[str, ...] = (),
    *,
    product: str | None = None,
) -> IdentityResolution:
    return IdentityResolution(
        canonical_product=product,
        canonical_vendor="upstream" if product else None,
        cpe_candidates=cpes,
        confidence="HIGH",
        rule_id=f"test.{status}",
        evidence=(),
        resolution_status=status,
    )


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


def test_sboms_preserve_observed_identity_and_use_shared_cpe_selection() -> None:
    scan_result = ScanResult(
        components=(
            Component(
                "observed-governed",
                "1.0",
                cpe="cpe:legacy:singular",
                cpe_candidates=("cpe:legacy:two", "cpe:legacy:one"),
                identity_resolution=_identity(
                    "resolved",
                    ("cpe:governed:z", "cpe:governed:a", "cpe:governed:a"),
                    product="canonical-product",
                ),
            ),
            Component(
                "legacy-candidates",
                "2.0",
                cpe="cpe:legacy:b",
                cpe_candidates=("cpe:legacy:z", "cpe:legacy:a", "", "cpe:legacy:a"),
            ),
            Component("legacy-singular", "3.0", cpe="cpe:legacy:only"),
            Component("no-cpe", "4.0"),
            Component(
                "uclient-fetch",
                identity_resolution=_identity("unsupported"),
            ),
            Component(
                "hostapd-common",
                identity_resolution=_identity("ambiguous"),
            ),
            Component(
                "wpad-basic",
                identity_resolution=_identity("ambiguous"),
            ),
        ),
        vulnerabilities=(),
        risk_score="LOW",
    )
    result = GenerateSBOMUseCase(JsonSBOMGenerator()).execute(scan_result)
    cyclonedx = result.cyclonedx.content["components"]
    spdx = result.spdx.content["packages"]
    cyclonedx_by_name = {component["name"]: component for component in cyclonedx}
    spdx_by_name = {package["name"]: package for package in spdx}

    assert len(cyclonedx) == len(scan_result.components)
    assert len(spdx) == len(scan_result.components)
    assert [component["name"] for component in cyclonedx] == sorted(
        component.name for component in scan_result.components
    )
    assert [package["name"] for package in spdx] == sorted(
        component.name for component in scan_result.components
    )
    assert cyclonedx_by_name["observed-governed"]["version"] == "1.0"
    assert "canonical-product" not in cyclonedx_by_name
    assert cyclonedx_by_name["observed-governed"]["cpe"] == "cpe:governed:a"
    assert cyclonedx_by_name["legacy-candidates"]["cpe"] == "cpe:legacy:a"
    assert cyclonedx_by_name["legacy-singular"]["cpe"] == "cpe:legacy:only"
    for name in ("no-cpe", "uclient-fetch", "hostapd-common", "wpad-basic"):
        assert "cpe" not in cyclonedx_by_name[name]

    assert spdx_by_name["observed-governed"]["versionInfo"] == "1.0"
    assert spdx_by_name["observed-governed"]["externalRefs"] == [
        {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:governed:a",
        },
        {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:governed:z",
        },
    ]
    legacy_references = spdx_by_name["legacy-candidates"]["externalRefs"]
    assert [reference["referenceLocator"] for reference in legacy_references] == [
        "cpe:legacy:a",
        "cpe:legacy:b",
        "cpe:legacy:z",
    ]
    for name in ("no-cpe", "uclient-fetch", "hostapd-common", "wpad-basic"):
        assert "externalRefs" not in spdx_by_name[name]
