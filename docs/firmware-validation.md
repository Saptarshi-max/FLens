# Firmware validation

The ARM64 Docker environment validated a 15-image corpus: 11 scans succeeded and four extraction
failures were diagnosed. AP96 changed from 147 merged components in the preserved Windows rootfs to
224 after fresh Linux extraction; this is an extraction-fidelity observation, not a scanner-policy
change. See `output/docker-smoke/ap96-extraction-comparison.*` and
`output/sample-scans/extraction-failure-diagnostics.*` locally.
