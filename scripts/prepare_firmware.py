"""Safely prepare user-supplied, officially obtained firmware archives."""

import argparse

from firmware_corpus import (
    FIRMWARE,
    INBOX,
    MANIFESTS,
    archive_candidates,
    atomic_json,
    extract_selected_zip,
    load_sources,
    safe_name,
    sha256,
)

parser = argparse.ArgumentParser()
parser.add_argument("--all", action="store_true")
parser.add_argument("--id")
args = parser.parse_args()

records: list[dict[str, object]] = []
for entry in load_sources():
    if args.id and entry["id"] != args.id:
        continue

    accepted = set(entry["accepted_firmware_extensions"])
    matches: list[tuple[object, str | None]] = []
    for candidate in INBOX.glob("*"):
        if candidate.suffix.lower() == ".zip":
            members = archive_candidates(
                candidate, accepted, entry.get("preferred_filename_pattern")
            )
            if len(members) == 1:
                matches.append((candidate, members[0]))
        elif candidate.suffix.lower().lstrip(".") in accepted:
            matches.append((candidate, None))

    if len(matches) != 1:
        status = "manual_download_required" if not matches else "validation_failed"
        records.append(
            {
                "id": entry["id"],
                "status": status,
                "error": "No unique firmware payload found in inbox.",
            }
        )
        continue

    source, member = matches[0]
    target = (
        FIRMWARE
        / str(entry["project"]).lower().replace(" ", "-")
        / str(entry["id"])
        / safe_name(member or source.name)
    )
    image = extract_selected_zip(source, member, target) if member else target
    if member is None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    records.append(
        {
            "id": entry["id"],
            "status": "downloaded",
            "source_page": entry["source_page"],
            "requested_url": None,
            "final_url": None,
            "selected_firmware_image": str(image),
            "sha256": sha256(image),
            "file_size": image.stat().st_size,
            "content_type": None,
            "archive_members": [member] if member else [],
            "discarded_members": [],
            "error": None,
            "manual_download_instructions": "User-supplied; source confirmation required.",
        }
    )

atomic_json(MANIFESTS / "firmware-downloads.json", records)
