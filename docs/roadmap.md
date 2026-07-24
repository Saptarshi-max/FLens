# FLENS Roadmap

## Phase 1 (completed)

- Rootfs component detection
- Static version resolution
- JSON-based CVE matching
- Risk scoring engine
- CLI + HTML report + starter API

## Phase 2 (completed)

- Firmware image extraction (binwalk integration)
- Extraction workflow orchestration and provenance tracking

## Phase 3 (completed)

- SBOM generation (SPDX, CycloneDX JSON)
- Firmware metadata extraction (filesystem, kernel, vendor hints)
- ELF-assisted component identification fallback
- SQLite persistence for reports and artifacts
- API endpoints for firmware upload and report retrieval

## Phase 4 (next)

- Secret scanning in extracted filesystem
- Structured findings and confidence scoring

## Phase 5

- Firmware A vs B comparison
- Delta vulnerabilities and package change intelligence

## Phase 6

- FastAPI-backed web platform
- Background workers and scan history
- Dashboard and multi-scan analytics
