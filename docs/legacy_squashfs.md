# Legacy SquashFS extraction

FLENS uses `unsquashfs` first and falls back to `sasquatch` for SquashFS v3 and vendor-modified filesystems. The Docker image builds Sasquatch from `https://github.com/devttys0/sasquatch` at commit `bd864a1b037bf57ca7d64a292a60ba0d6459611f` (GPL-2.0-only). Verify it with `docker run --rm --entrypoint sasquatch flens:docker -version`.

Extraction is successful only when a carved payload produces meaningful root filesystem entries such as `bin`, `sbin`, `etc`, `lib`, or `usr`. Firmware is never modified; payloads are carved into the extraction workspace. Some proprietary formats or encrypted images remain unsupported.
