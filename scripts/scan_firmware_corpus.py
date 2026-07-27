"""Run FLENS against firmware prepared in the local corpus directory."""

import argparse
import json
import subprocess
import time
from pathlib import Path

from firmware_corpus import MANIFESTS, ROOT, atomic_json, sha256

parser = argparse.ArgumentParser()
parser.add_argument("--engine", choices=("local", "docker"), default="local")
parser.add_argument("--timeout", type=int, default=1800)
args = parser.parse_args()

downloads_path = MANIFESTS / "firmware-downloads.json"
downloads = json.loads(downloads_path.read_text()) if downloads_path.exists() else []
results: list[dict[str, object]] = []
for item in downloads:
    image = item.get("selected_firmware_image")
    if not image or not Path(image).is_file():
        continue

    report = ROOT / "output" / "firmware-reports" / f"{item['id']}.html"
    report.parent.mkdir(parents=True, exist_ok=True)
    command = ["flens", "firmware", str(image), "--report-out", str(report)]
    started = time.time()
    try:
        run = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=args.timeout,
            check=False,
        )
        status = "succeeded" if run.returncode == 0 else "extraction_failed"
    except subprocess.TimeoutExpired:
        status = "timed_out"
        run = None

    results.append(
        {
            "firmware_id": item["id"],
            "firmware_path": image,
            "firmware_sha256": sha256(Path(image)),
            "report_path": str(report) if report.exists() else None,
            "scan_status": status,
            "duration_seconds": round(time.time() - started, 3),
            "FLENS_command": command,
            "error": None if run is None else run.stderr,
        }
    )

atomic_json(MANIFESTS / "firmware-scan-results.json", results)
