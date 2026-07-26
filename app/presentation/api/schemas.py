from pydantic import BaseModel


class ComponentSchema(BaseModel):
    name: str
    version: str
    confidence: str
    evidence: list[dict[str, str]]
    cpe: str | None = None
    cpe_candidates: list[str] = []
    cpe_confidence: str = "LOW"


class VulnerabilitySchema(BaseModel):
    cve_id: str
    severity: str
    description: str
    component_name: str
    component_version: str
    confidence: str
    evidence: list[dict[str, str]]
    cvss: float | None = None
    affected_range: str = "Unknown"
    match_result: str = "Unknown"
    data_source: str = "Unknown"
    reasoning: str = "Unknown"


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
