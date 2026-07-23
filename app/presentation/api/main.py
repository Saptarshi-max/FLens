from pathlib import Path

from fastapi import FastAPI

from app.config.container import Container
from app.presentation.api.schemas import (
    ComponentSchema,
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

    return ScanResponseSchema(
        components=[ComponentSchema(name=c.name, version=c.version) for c in result.components],
        vulnerabilities=[
            VulnerabilitySchema(
                cve_id=v.cve_id,
                severity=v.severity,
                description=v.description,
            )
            for v in result.vulnerabilities
        ],
        risk_score=result.risk_score,
    )
