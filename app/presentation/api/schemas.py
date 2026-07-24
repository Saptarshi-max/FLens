from pydantic import BaseModel


class ComponentSchema(BaseModel):
    name: str
    version: str


class VulnerabilitySchema(BaseModel):
    cve_id: str
    severity: str
    description: str


class FirmwareMetadataSchema(BaseModel):
    architecture: str
    filesystem_type: str
    kernel_information: str
    vendor_information: str


class SBOMSchema(BaseModel):
    format: str
    content: dict[str, object]


class ScanResponseSchema(BaseModel):
    components: list[ComponentSchema]
    vulnerabilities: list[VulnerabilitySchema]
    risk_score: str
    report_id: int | None = None


class ScanRequestSchema(BaseModel):
    rootfs_path: str


class ReportResponseSchema(BaseModel):
    report_id: int
    risk_score: str
    components: list[ComponentSchema]
    vulnerabilities: list[VulnerabilitySchema]
    sboms: list[SBOMSchema]
    firmware_metadata: FirmwareMetadataSchema | None


class FirmwareUploadResponseSchema(BaseModel):
    report_id: int
    risk_score: str
