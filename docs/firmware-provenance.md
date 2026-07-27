# Firmware provenance

## Included synthetic fixtures

| Path | Purpose | Format | Origin | Real firmware | Redistribution basis |
|---|---|---|---|---|---|
| `sample_data/rootfs/` | Deterministic detector fixture | Small text placeholders | FLENS tests | No | Project fixture |
| `sample_data/firmware/sample_router.bin` | Extraction-failure fixture | Text | FLENS tests | No | Project fixture |
| `sample_data/uploads/router.bin` | Upload-path fixture | Text | FLENS tests | No | Project fixture |

## External validation corpus

Third-party images used in local Docker validation are **not included** in the intended public
repository set. Their redistribution permission is `Unknown - manual provenance record required`
unless an approved record says otherwise. See `docs/release-evidence/v0.3.0-alpha/` for filenames,
hashes where retained, statuses, and validation results.

FLENS does not assert redistribution rights for third-party firmware. Vendor and community images
are excluded from the intended public release set unless their origin, hash, and redistribution
basis are explicitly approved. Users may mount their own legally obtained `sample_data/` directory
into Docker or Compose.

| Item | Classification | Release policy |
|---|---|---|
| `sample_data/rootfs/` | `KEEP_SYNTHETIC_FIXTURE` | Small FLENS test fixture. |
| `sample_data/firmware/sample_router.bin` | `KEEP_SYNTHETIC_FIXTURE` | Tiny synthetic extraction-failure fixture. |
| `sample_data/uploads/router.bin` | `KEEP_SYNTHETIC_FIXTURE` | Tiny synthetic fixture; do not treat as firmware. |
| `sample_data/firmware/openwrt/*.bin` | `MANUAL_REVIEW_REQUIRED` | Open-source origin is documented in manifests, but binaries need hash/provenance approval before commit. |
| `sample_data/firmware/dd-wrt/*.bin` | `MANUAL_REVIEW_REQUIRED` | Download provenance/licence must be approved before publication. |
| Root-level vendor/community `*.bin` files | `REMOVE_FROM_PUBLIC_RELEASE` | Keep local-only; provide download instructions and hashes after approval. |

The source manifests identify known upstream pages. Release evidence records hashes and diagnostics
for validation; it does not grant redistribution permission.

### Individual external-image records

Every third-party image currently present in a developer checkout is excluded from the intended
public release until a source URL, SHA-256, and redistribution basis have been reviewed. `Known`
below means a source page is recorded in a local manifest; it does **not** mean redistribution has
been approved.

| Image | Source URL | SHA-256 record | Redistribution | Public-release action |
|---|---|---|---|---|
| `c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin` | Manual review required | Manual review required | Unknown | Exclude |
| `carambola2-sysupgrade.bin` | Manual review required | Local validation only | Unknown | Exclude |
| `DIR878A1_FW100B13.bin` | Manual review required | Local validation only | Unknown | Exclude |
| `firmware/dd-wrt/netgear-r6400v2-webflash.bin` | DD-WRT provenance review | Local validation only | Unknown | Exclude |
| `firmware/dd-wrt/netgear-r7000-webflash.bin` | DD-WRT provenance review | Local validation only | Unknown | Exclude |
| `firmware/openwrt/openwrt-ap96-19.07.10.bin` | OpenWrt source page in manifest | Local validation only | Manual review required | Exclude pending approval |
| `firmware/openwrt/openwrt-meraki-mr16-19.07.10.bin` | OpenWrt provenance review | Local validation only | Manual review required | Exclude pending approval |
| `firmware/openwrt/openwrt-onion-omega-19.07.10.bin` | OpenWrt provenance review | Local validation only | Manual review required | Exclude pending approval |
| `firmware/openwrt/openwrt-packet-squirrel-19.07.10.bin` | OpenWrt provenance review | Local validation only | Manual review required | Exclude pending approval |
| `linksys_ea6500_cfe.bin` | Manual review required | Local validation only | Unknown | Exclude |
| `linksys_ea6500_ddwrt.bin` | Manual review required | Local validation only | Unknown | Exclude |
| `openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade.bin` | OpenWrt source page in manifest | Local validation only | Manual review required | Exclude pending approval |
| `wa701nv2_en_3_17_0_up_boot(140324).bin` | TP-Link source page in manifest | Local validation only | Unknown | Exclude |

## Supplying firmware locally

Place legally obtained files under `sample_data/`, bind-mount a separate host directory in Docker,
or set `FLENS_INPUT_DIR` in Docker Compose. FLENS does not download vendor firmware automatically.
