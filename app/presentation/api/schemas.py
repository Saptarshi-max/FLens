from pydantic import BaseModel


class ComponentSchema(BaseModel):
    name: str
    version: str


class VulnerabilitySchema(BaseModel):
    cve_id: str
    severity: str
    description: str


class ScanResponseSchema(BaseModel):
    components: list[ComponentSchema]
    vulnerabilities: list[VulnerabilitySchema]
    risk_score: str


class ScanRequestSchema(BaseModel):
    rootfs_path: str
