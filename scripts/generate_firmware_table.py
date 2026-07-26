import json
from firmware_corpus import MANIFESTS, ROOT, atomic_json, load_sources

downloads = {item["id"]: item for item in json.loads((MANIFESTS / "firmware-downloads.json").read_text())} if (MANIFESTS / "firmware-downloads.json").exists() else {}
scans = {item["firmware_id"]: item for item in json.loads((MANIFESTS / "firmware-scan-results.json").read_text())} if (MANIFESTS / "firmware-scan-results.json").exists() else {}
lines=["## Firmware Validation Matrix", "", "| Project / Vendor | Device / Target | Firmware Version | Image File | SHA-256 | FLENS Report | Status |", "|---|---|---|---|---|---|---|"]
for entry in load_sources():
    download=downloads.get(entry["id"],{}); scan=scans.get(entry["id"],{}); status=scan.get("scan_status", download.get("status","Not yet scanned"))
    icon={"succeeded":"✅","manual_download_required":"🖐","extraction_failed":"❌"}.get(status,"⏳")
    image=download.get("selected_firmware_image","Unknown"); report=scan.get("report_path")
    link=f"[HTML]({report})" if report else "_Pending_"
    lines.append(f"| {entry['project']} | {entry['device']} | {entry['version']} | `{image}` | `{download.get('sha256','Unknown')}` | {link} | {icon} {status} |")
table="\n".join(lines)+"\n"; (ROOT / "output" / "firmware-validation-table.md").write_text(table,encoding="utf-8")
readme=ROOT / "README.md"; content=readme.read_text(encoding="utf-8"); start="<!-- FIRMWARE_VALIDATION_START -->"; end="<!-- FIRMWARE_VALIDATION_END -->"
section=f"{start}\n\n{table}\n{end}"
if start in content and end in content: content=content[:content.index(start)]+section+content[content.index(end)+len(end):]
else: content += f"\n\n{section}\n"
readme.write_text(content,encoding="utf-8")
