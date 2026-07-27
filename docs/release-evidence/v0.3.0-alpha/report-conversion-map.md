# HTML-to-PDF conversion map

The converter uses local HTML reports only. Failed extraction inputs have no HTML report and are
intentionally excluded from PDF conversion.

| Firmware | Original firmware input | Local HTML report | Target PDF | Conversion status |
|---|---|---|---|---|
| TP-Link Archer C7 v5 | `c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43.bin` | `output/sample-scans/c7v5_us-up-ver1-2-1-P1[20220715-rel19099]_2022-07-15_17.44.43-5fd4c55b5f/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-archer-c7-v5-report.pdf` | Converted |
| 8devices Carambola 2 | `carambola2-sysupgrade.bin` | `output/sample-scans/carambola2-sysupgrade-79215be2ef/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-carambola2-report.pdf` | Converted |
| Netgear R6400v2 DD-WRT | `firmware/dd-wrt/netgear-r6400v2-webflash.bin` | `output/sample-scans/netgear-r6400v2-webflash-67b941d30f/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-netgear-r6400v2-ddwrt-report.pdf` | Converted |
| Netgear R7000 DD-WRT | `firmware/dd-wrt/netgear-r7000-webflash.bin` | `output/sample-scans/netgear-r7000-webflash-ccc222648b/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-netgear-r7000-ddwrt-report.pdf` | Converted |
| ALFA AP96 OpenWrt 19.07.10 | `firmware/openwrt/openwrt-ap96-19.07.10.bin` | `output/sample-scans/openwrt-ap96-19.07.10-54b90d4297/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-ap96-19.07.10-report.pdf` | Converted |
| Meraki MR16 OpenWrt 19.07.10 | `firmware/openwrt/openwrt-meraki-mr16-19.07.10.bin` | `output/sample-scans/openwrt-meraki-mr16-19.07.10-63e2a31c9d/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-meraki-mr16-19.07.10-report.pdf` | Converted |
| Onion Omega OpenWrt 19.07.10 | `firmware/openwrt/openwrt-onion-omega-19.07.10.bin` | `output/sample-scans/openwrt-onion-omega-19.07.10-d0dddc1288/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-onion-omega-19.07.10-report.pdf` | Converted |
| Packet Squirrel OpenWrt 19.07.10 | `firmware/openwrt/openwrt-packet-squirrel-19.07.10.bin` | `output/sample-scans/openwrt-packet-squirrel-19.07.10-5f93ebe640/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-packet-squirrel-19.07.10-report.pdf` | Converted |
| Linksys EA6500 DD-WRT | `linksys_ea6500_ddwrt.bin` | `output/sample-scans/linksys_ea6500_ddwrt-9ab0a1428c/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-linksys-ea6500-ddwrt-report.pdf` | Converted |
| ALFA AP96 sysupgrade OpenWrt 19.07.10 | `openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade.bin` | `output/sample-scans/openwrt-19.07.10-ar71xx-generic-alfa-ap96-squashfs-sysupgrade-5794181e85/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-openwrt-ap96-sysupgrade-19.07.10-report.pdf` | Converted |
| TP-Link TL-WA701ND v2 | `wa701nv2_en_3_17_0_up_boot(140324).bin` | `output/sample-scans/wa701nv2_en_3_17_0_up_boot(140324)-5ac5257880/report.html` | `docs/release-evidence/v0.3.0-alpha/reports/flens-tplink-tl-wa701nd-v2-report.pdf` | Converted |
| D-Link DIR-878 A1 | `DIR878A1_FW100B13.bin` | — | — | Extraction failed - no report generated |
| Synthetic extraction fixture | `firmware/sample_router.bin` | — | — | Extraction failed - no report generated |
| Linksys EA6500 CFE | `linksys_ea6500_cfe.bin` | — | — | Extraction failed - no report generated |
| Synthetic upload fixture | `uploads/router.bin` | — | — | Extraction failed - no report generated |

## Installation

```powershell
uv sync --extra dev
uv run playwright install chromium
python tools/convert_reports_to_pdf.py --overwrite
```

`FLENS_CHROMIUM_EXECUTABLE` can point Playwright at an already-installed Chromium-compatible
browser when the managed Chromium download is unavailable. The converter blocks external network
requests and renders only local `file:` resources.
