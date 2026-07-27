# Extraction failure diagnostics

| Firmware | Size | File type | Signatures | Classification | Confidence | Batch reason |
|---|---:|---|---|---|---|---|
| DIR878A1_FW100B13.bin | 9651099 | u-boot legacy uImage, Linux/MIPS kernel, LZMA | uImage @0, LZMA @0xA0 | valid firmware but no supported filesystem extracted | high | Empty extraction result. |
| firmware/sample_router.bin | 28 | ASCII text with CRLF | none | likely synthetic fixture | high | Empty extraction result. |
| linksys_ea6500_cfe.bin | 232049 | data | LZMA @0x24004 | likely bootloader-only | medium | Empty extraction result. |
| uploads/router.bin | 14 | ASCII text | none | likely synthetic fixture | high | Empty extraction result. |
