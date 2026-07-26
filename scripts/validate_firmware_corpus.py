from firmware_corpus import FIRMWARE, sha256
for path in FIRMWARE.rglob("*"):
    if path.is_file(): print(f"{path}: {path.stat().st_size} bytes sha256={sha256(path)}")
