# FLENS Architecture (Phase 3)

```mermaid
flowchart LR
    FW[Firmware Image] --> FIUC[AnalyzeFirmwareIntelligenceUseCase]
    FIUC --> EXUC[AnalyzeFirmwareUseCase]
    EXUC --> FEP[FirmwareExtractor Protocol]
    FEP --> BIN[BinwalkExtractor]
    BIN --> FS[FilesystemDetector]
    EXUC --> FMEP[FirmwareMetadataExtractor Protocol]
    FMEP --> RFME[RootfsFirmwareMetadataExtractor]
    EXUC --> UC[ScanFirmwareUseCase]
    FIUC --> GSBOM[GenerateSBOMUseCase]
    GSBOM --> SGP[SBOMGenerator Protocol]
    SGP --> JSG[JsonSBOMGenerator]
    FIUC --> SSCAN[StoreScanUseCase]
    SSCAN --> SRP[ScanRepository Protocol]
    SRP --> SQLR[SQLAlchemyScanRepository]
    SQLR --> DB[(SQLite)]

    CLI[Typer CLI] --> UC
    CLI --> EXUC
    API[FastAPI API] --> UC
    API --> FIUC
    API --> SRP

    UC --> CD[ComponentDetector Port]
    UC --> VP[VulnerabilityProvider Port]
    UC --> RE[RiskEngine]

    CD --> FCD[FileSystemComponentDetector]
    FCD --> ELF[ELFAnalyzer]
    FCD --> VR[VersionResolver Port]
    VR --> SVR[StaticVersionResolver]

    VP --> JVP[JsonVulnerabilityProvider]
    JVP --> CVE[(cve_db.json)]

    UC --> SR[ScanResult Entity]
    FIUC --> SBOMDOC[SBOMDocument Entity]
    SR --> RG[ReportGenerator Port]
    RG --> HRG[HtmlReportGenerator]
    HRG --> HTML[report.html]
```

## Principles Applied

- Dependency inversion: use case depends on ports, not adapters.
- Immutable domain entities: frozen dataclasses with stable value semantics.
- Swappable infrastructure: CVE source and version strategy are replaceable.
- Modular extraction backend: firmware extraction isolated from business scan logic.
- Persisted intelligence: scan artifacts are queryable through a repository contract.
- Multi-artifact output: a single workflow emits report data and SBOM formats.
- Testability: no global state, constructor injection only.
- Separation of concerns: scan orchestration, scoring, reporting, and IO are isolated.

## Interface Stability

FLENS includes forward-compatible interfaces in `app/domain/interfaces/future_interfaces.py` for SBOMs, secret scanning, comparison, and feed updates.
Firmware extraction is now promoted into its own contract in `app/domain/interfaces/firmware_extractor.py`.
Phase 3 adds stable contracts for SBOM generation, metadata extraction, and scan persistence.

## Firmware Pipeline

```text
Firmware Image
    |
    v
Extraction + Metadata Engine
    |
    v
Component Scanner
    |
    v
CVE Engine
    |
    v
SBOM + Report + Persistence
```
