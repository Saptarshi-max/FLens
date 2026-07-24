# SBOM Methodology

## What Is an SBOM?

A Software Bill of Materials (SBOM) is a structured inventory of software components and versions included in an artifact.

In FLENS, SBOMs are generated from detected firmware components in scan results.

## Why Firmware Projects Need SBOMs

- Security review: map components to known vulnerabilities.
- Compliance: support internal and external audit requirements.
- Release governance: track component drift across firmware releases.
- Incident response: quickly identify impacted products when new CVEs are published.

## Supported Formats

FLENS generates two JSON SBOM formats:

- SPDX JSON
- CycloneDX JSON

## SPDX vs CycloneDX

- SPDX is commonly used for licensing and compliance workflows.
- CycloneDX is commonly used for software supply-chain and vulnerability tooling.
- Producing both improves interoperability with downstream systems.

## Output Examples

When SBOM export is enabled, FLENS writes:

```text
report.spdx.json
report.cyclonedx.json
```

## CLI Usage

```bash
flens scan sample_data/rootfs --sbom-out output
flens firmware sample_data/firmware/sample_router.bin --report-out output/report.html --sbom-out output
```
