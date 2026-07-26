from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.config.container import Container
from app.domain.entities.component import Component
from app.domain.entities.extraction_result import ExtractionResult
from app.domain.entities.vulnerability import Vulnerability
from app.domain.sbom.models import SBOMDocument
from app.presentation.api.schemas import (
    ComponentSchema,
    FirmwareMetadataSchema,
    FirmwareUploadResponseSchema,
    ReportResponseSchema,
    SBOMSchema,
    ScanRequestSchema,
    ScanResponseSchema,
    VulnerabilitySchema,
)

api = FastAPI(title="FLENS API", version="0.1.0")


@api.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@api.post("/scan", response_model=ScanResponseSchema)
def scan_firmware(payload: ScanRequestSchema) -> ScanResponseSchema:
    container = Container()
    use_case = container.build_scan_use_case()
    result = use_case.execute(Path(payload.rootfs_path))
    sbom_result = container.build_generate_sbom_use_case().execute(result)
    report_id = container.build_store_scan_use_case().execute(
        extraction_result=ExtractionResult(
            firmware_path=Path(payload.rootfs_path),
            extracted_path=Path(payload.rootfs_path),
            filesystem_type="Unknown",
            architecture="Unknown",
            metadata={"source": "api_scan"},
        ),
        scan_result=result,
        firmware_metadata=None,
        sboms=[sbom_result.cyclonedx, sbom_result.spdx],
    )

    return ScanResponseSchema(
        components=[_component_to_schema(c) for c in result.components],
        vulnerabilities=[_vulnerability_to_schema(v) for v in result.vulnerabilities],
        risk_score=result.risk_score,
        report_id=report_id,
    )


@api.post("/firmware/upload", response_model=FirmwareUploadResponseSchema)
async def upload_firmware_and_scan(
    firmware_file: Annotated[UploadFile, File(...)],
) -> FirmwareUploadResponseSchema:
    container = Container()
    upload_dir = container.settings.upload_work_dir
    upload_dir.mkdir(parents=True, exist_ok=True)

    filename = firmware_file.filename or "uploaded_firmware.bin"
    destination = upload_dir / filename
    file_content = await firmware_file.read()
    destination.write_bytes(file_content)

    intelligence = container.build_firmware_intelligence_use_case().execute(destination)
    return FirmwareUploadResponseSchema(
        report_id=intelligence.report_id,
        risk_score=intelligence.analysis.scan_result.risk_score,
    )


@api.get("/reports/{report_id}", response_model=ReportResponseSchema)
def get_report(report_id: int) -> ReportResponseSchema:
    container = Container()
    report = container.build_scan_repository().get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    return ReportResponseSchema(
        report_id=report.report_id,
        risk_score=report.risk_score,
        components=[_component_to_schema(c) for c in report.components],
        vulnerabilities=[_vulnerability_to_schema(v) for v in report.vulnerabilities],
        sboms=[_sbom_to_schema(sbom) for sbom in report.sboms],
        firmware_metadata=(
            FirmwareMetadataSchema(
                architecture=report.firmware_metadata.architecture,
                filesystem_type=report.firmware_metadata.filesystem_type,
                kernel_information=report.firmware_metadata.kernel_information,
                vendor_information=report.firmware_metadata.vendor_information,
            )
            if report.firmware_metadata is not None
            else None
        ),
    )


def _sbom_to_schema(sbom: SBOMDocument) -> SBOMSchema:
    return SBOMSchema(format=sbom.format.value, content=sbom.content)


def _component_to_schema(component: Component) -> ComponentSchema:
    return ComponentSchema(
        name=component.name,
        version=component.version,
        confidence=component.confidence,
        evidence=[
            {"source": item.source, "path": item.path, "detail": item.detail}
            for item in component.evidence
        ],
        cpe=component.cpe,
        cpe_candidates=list(component.cpe_candidates),
        cpe_confidence=component.cpe_confidence,
    )


def _vulnerability_to_schema(vulnerability: Vulnerability) -> VulnerabilitySchema:
    return VulnerabilitySchema(
        cve_id=vulnerability.cve_id,
        severity=vulnerability.severity,
        description=vulnerability.description,
        component_name=vulnerability.component_name,
        component_version=vulnerability.component_version,
        confidence=vulnerability.confidence,
        evidence=[
            {"source": item.source, "path": item.path, "detail": item.detail}
            for item in vulnerability.evidence
        ],
        cvss=vulnerability.cvss,
        affected_range=vulnerability.affected_range,
        match_result=vulnerability.match_result,
        data_source=vulnerability.data_source,
        reasoning=vulnerability.reasoning,
    )
