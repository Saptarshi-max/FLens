"""Generate the firmware validation matrix and update the README section."""

import json

from firmware_corpus import MANIFESTS, ROOT, load_sources

downloads_path = MANIFESTS / "firmware-downloads.json"
downloads = (
    {item["id"]: item for item in json.loads(downloads_path.read_text())}
    if downloads_path.exists()
    else {}
)
scans_path = MANIFESTS / "firmware-scan-results.json"
scans = (
    {item["firmware_id"]: item for item in json.loads(scans_path.read_text())}
    if scans_path.exists()
    else {}
)
lines = [
    "## Firmware Validation Matrix",
    "",
    (
        "| Project / Vendor | Device / Target | Firmware Version | Image File | "
        "SHA-256 | FLENS Report | Status |"
    ),
    "|---|---|---|---|---|---|---|",
]
for entry in load_sources():
    download = downloads.get(entry["id"], {})
    scan = scans.get(entry["id"], {})
    status = scan.get("scan_status", download.get("status", "Not yet scanned"))
    icon = {
        "succeeded": "âœ…",
        "manual_download_required": "ðŸ–",
        "extraction_failed": "âŒ",
    }.get(status, "â³")
    image = download.get("selected_firmware_image", "Unknown")
    report = scan.get("report_path")
    link = f"[HTML]({report})" if report else "_Pending_"
    lines.append(
        f"| {entry['project']} | {entry['device']} | {entry['version']} | "
        f"`{image}` | `{download.get('sha256', 'Unknown')}` | {link} | "
        f"{icon} {status} |"
    )

table = "\n".join(lines) + "\n"
table_path = ROOT / "output" / "firmware-validation-table.md"
table_path.write_text(table, encoding="utf-8")

readme = ROOT / "README.md"
content = readme.read_text(encoding="utf-8")
start = "<!-- FIRMWARE_VALIDATION_START -->"
end = "<!-- FIRMWARE_VALIDATION_END -->"
section = f"{start}\n\n{table}\n{end}"
if start in content and end in content:
    content = content[: content.index(start)] + section + content[
        content.index(end) + len(end) :
    ]
else:
    content += f"\n\n{section}\n"
readme.write_text(content, encoding="utf-8")
