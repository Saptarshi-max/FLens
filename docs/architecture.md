# FLENS Architecture (Phase 2)

```mermaid
flowchart LR
    FW[Firmware Image] --> EXUC[AnalyzeFirmwareUseCase]
    EXUC --> FEP[FirmwareExtractor Protocol]
    FEP --> BIN[BinwalkExtractor]
    BIN --> FS[FilesystemDetector]
    EXUC --> UC[ScanFirmwareUseCase]
    CLI[Typer CLI] --> UC
    CLI --> EXUC
    API[FastAPI API] --> UC

    UC --> CD[ComponentDetector Port]
    UC --> VP[VulnerabilityProvider Port]
    UC --> RE[RiskEngine]

    CD --> FCD[FileSystemComponentDetector]
    FCD --> VR[VersionResolver Port]
    VR --> SVR[StaticVersionResolver]

    VP --> JVP[JsonVulnerabilityProvider]
    JVP --> CVE[(cve_db.json)]

    UC --> SR[ScanResult Entity]
    SR --> RG[ReportGenerator Port]
    RG --> HRG[HtmlReportGenerator]
    HRG --> HTML[report.html]
```

## Principles Applied

- Dependency inversion: use case depends on ports, not adapters.
- Immutable domain entities: frozen dataclasses with stable value semantics.
- Swappable infrastructure: CVE source and version strategy are replaceable.
- Modular extraction backend: firmware extraction isolated from business scan logic.
- Testability: no global state, constructor injection only.
- Separation of concerns: scan orchestration, scoring, reporting, and IO are isolated.

## Future Interface Stability

FLENS includes forward-compatible interfaces in `app/domain/interfaces/future_interfaces.py` for SBOMs, secret scanning, comparison, and feed updates.
Firmware extraction is now promoted into its own contract in `app/domain/interfaces/firmware_extractor.py`.

## Firmware Pipeline

```text
Firmware Image
    |
    v
Extraction Engine
    |
    v
Component Scanner
    |
    v
CVE Engine
    |
    v
Report
```
