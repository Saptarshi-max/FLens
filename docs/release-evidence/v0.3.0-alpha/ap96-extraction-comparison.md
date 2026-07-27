# AP96 extraction comparison

- Existing rootfs: 147 merged components
- Fresh Docker extraction: 224 merged components
- Delta: +77
- Known versions: 110 ? 110
- Unknown versions: 37 ? 114
- Governed CPEs: 3 ? 3
- Vulnerabilities: 0 ? 0

The fresh Linux extraction differs from the Windows-preserved rootfs. The batch artefact stores aggregates only, so per-component additions/removals and filesystem diagnostic deltas are unavailable without a detailed Docker inventory export. The additional 77 entries require validation; they are not assumed to be valid new software.
