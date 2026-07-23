# FLENS

### Firmware Linux Embedded Security

Analyze embedded Linux firmware, identify software components, map known vulnerabilities, and generate actionable security reports.

FLENS is a Python-based firmware security analysis platform designed for embedded Linux systems such as routers, IoT gateways, industrial controllers, cameras, and edge devices.

The project aims to bring firmware security closer to embedded software development by combining component discovery, vulnerability identification, risk assessment, and reporting into an extensible engineering workflow.

---

## Why FLENS?

![flens-logo](/flens.jpeg)

Firmware often contains hundreds of third-party components:

* OpenSSL
* BusyBox
* Dropbear
* Curl
* Nginx
* Linux Kernel packages

Many products ship with outdated or vulnerable versions of these components, creating hidden security risks.

FLENS helps answer questions like:

* What software exists inside this firmware?
* Which versions are present?
* Are any known vulnerabilities affecting them?
* What is the overall risk profile?
* How does one firmware release compare to another?

## Where FLENS Fits

Existing firmware analysis tools are excellent at extracting and inspecting firmware images. However, embedded teams often need more than a one-time security scan.

FLENS focuses on the engineering workflow:

- Integrating firmware security checks into development pipelines
- Tracking component risks across firmware releases
- Generating actionable reports for developers and reviewers
- Providing an extensible foundation for SBOM, vulnerability management, and CI/CD security gates

Instead of treating firmware analysis as a manual security exercise, FLENS aims to make it part of the embedded software lifecycle.

Example workflow:

```
Yocto Build / Firmware Release
│
▼
FLENS Analysis
│
▼
Components + CVEs + Risk Score
│
▼
Security Report / Release Decision

```

FLENS bridges the gap between **firmware reverse engineering tools** and **everyday embedded software engineering workflows**.

---

## Current Capabilities

### Component Discovery

Automatically identifies known software components inside an extracted firmware filesystem.

Example:

```text
OpenSSL 1.1.1d
BusyBox 1.31.1
Dropbear 2020.79
```

### Vulnerability Mapping

Correlates detected software versions against a vulnerability database.

Example:

```text
OpenSSL 1.1.1d

→ CVE-2022-0778
→ CVE-2021-3711
```

### Risk Assessment

Calculates an overall firmware security score using configurable severity weighting.

Example:

```text
Risk Level: HIGH
```

### Report Generation

Produces human-readable HTML reports suitable for audits, reviews, and release validation.

---

## Example Scan

Input:

```text
rootfs/
├── bin/
│   ├── busybox
│   ├── openssl
│   └── dropbear
```

Output:

```text
──────────────────────────
FLENS Security Report
──────────────────────────

Detected Components

• BusyBox 1.31.1
• OpenSSL 1.1.1d
• Dropbear 2020.79

Detected Vulnerabilities

• CVE-2022-0778 (HIGH)
• CVE-2021-3711 (HIGH)

Overall Risk

HIGH
```

---

## Architecture

FLENS follows Clean Architecture principles to separate business logic from implementation details.

```text
Root Filesystem
        │
        ▼
Component Detection
        │
        ▼
Version Resolution
        │
        ▼
Vulnerability Mapping
        │
        ▼
Risk Assessment
        │
        ▼
HTML Report / API Response
```

Project Structure:

```text
flens/
├── app/
│   ├── domain/
│   ├── application/
│   ├── infrastructure/
│   ├── presentation/
│   └── config/
├── tests/
├── sample_data/
├── docs/
└── pyproject.toml
```

---

## Quick Start

Install:

```bash
pip install -e .[dev]
```

Run a scan:

```bash
flens scan sample_data/rootfs
```

Generate an HTML report:

```bash
flens scan sample_data/rootfs \
    --report-out report.html
```

---

## API

Run locally:

```bash
uvicorn app.presentation.api.main:api --reload
```

Open:

```text
http://localhost:8000/docs
```

Available endpoints:

```http
GET  /health
POST /scan
```

---

## Quality Standards

FLENS includes:

* Type hints
* Dependency injection
* Unit tests
* Integration tests
* Static analysis
* HTML reporting
* CI-ready structure

Validation:

```bash
ruff check .
mypy .
pytest -v
pytest --cov
```

---

## Roadmap

### Phase 1 — Foundation ✅

* Component detection
* Version resolution
* CVE matching
* Risk scoring
* CLI interface
* HTML reporting

### Phase 2 — Firmware Extraction

```text
firmware.bin
      │
      ▼
    Binwalk
      ▼
    rootfs
```

* Direct firmware analysis
* Filesystem extraction
* Metadata discovery

### Phase 3 — SBOM Generation

* SPDX
* CycloneDX
* License reporting

### Phase 4 — Secret Discovery

Detect:

* Private keys
* API keys
* Credentials
* Certificates

### Phase 5 — Firmware Diffing

Compare releases:

```text
Firmware A
     vs
Firmware B
```

Identify:

* Added packages
* Removed packages
* New vulnerabilities
* Fixed vulnerabilities

### Phase 6 — Security Platform

* Scan history
* Dashboard
* Multi-user support
* Automated analysis pipelines

---

## Technology Stack

* Python 3.12+
* FastAPI
* Pydantic
* Typer
* Jinja2
* Pytest
* Ruff
* MyPy

---

## Motivation

FLENS is designed for engineers building embedded Linux products who need visibility into the security posture of their firmware before deployment.

FLENS was created to explore the intersection of:

* Embedded Linux
* Firmware Analysis
* Software Supply Chain Security
* Vulnerability Management
* Modern Python Architecture

The long-term vision is to evolve FLENS into a comprehensive firmware security platform capable of analyzing, comparing, and monitoring embedded software releases at scale.

