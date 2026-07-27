"""Record safe firmware download requirements without downloading firmware."""

import argparse

from firmware_corpus import MANIFESTS, atomic_json, load_sources

parser = argparse.ArgumentParser(
    description="Record safe firmware download requirements."
)
parser.add_argument("--all", action="store_true")
parser.add_argument("--id")
args = parser.parse_args()

records: list[dict[str, object]] = []
for entry in load_sources():
    if args.id and entry["id"] != args.id:
        continue
    status = "manual_download_required" if entry["download_mode"] == "manual" else "skipped"
    records.append(
        {
            "id": entry["id"],
            "status": status,
            "source_page": entry["source_page"],
            "requested_url": entry["download_url"],
            "final_url": None,
            "error": None,
            "manual_download_instructions": (
                f"Download only from {entry['source_page']} and place the archive/image "
                "in sample_data/firmware-inbox/."
            ),
        }
    )
    print(f"{entry['id']}: {status}")

atomic_json(MANIFESTS / "firmware-downloads.json", records)
