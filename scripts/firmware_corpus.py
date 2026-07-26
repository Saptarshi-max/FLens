"""Safe, offline-first helpers shared by the firmware corpus commands."""
import hashlib
import json
import fnmatch
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "sample_data" / "manifests"
FIRMWARE = ROOT / "sample_data" / "firmware"
INBOX = ROOT / "sample_data" / "firmware-inbox"
ALLOWED = {".bin", ".img", ".trx", ".chk", ".ubi", ".itb"}

def load_sources() -> list[dict[str, object]]:
    """The YAML manifest uses JSON syntax, a strict YAML subset, to avoid hidden parsers."""
    return json.loads((MANIFESTS / "firmware-sources.yaml").read_text(encoding="utf-8"))["firmware"]

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def safe_name(name: str) -> str:
    value = Path(name).name
    if value != name or not value or value in {".", ".."}:
        raise ValueError("unsafe filename")
    return value

def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)

def archive_candidates(archive: Path, accepted: set[str], pattern: str | None = None) -> list[str]:
    """Return safe archive members; never extract links or traversal paths."""
    if archive.suffix.lower() != ".zip":
        raise ValueError("only ZIP archives are currently supported")
    with zipfile.ZipFile(archive) as bundle:
        if len(bundle.infolist()) > 1000:
            raise ValueError("archive has too many members")
        names=[]
        for member in bundle.infolist():
            name=member.filename
            if Path(name).is_absolute() or ".." in Path(name).parts or member.is_dir(): continue
            if member.file_size > 512 * 1024 * 1024: raise ValueError("archive member too large")
            if Path(name).suffix.lower().lstrip(".") in accepted:
                names.append(name)
        if pattern:
            matched=[name for name in names if fnmatch.fnmatch(Path(name).name, pattern)]
            if matched: names=matched
        return names

def extract_selected_zip(archive: Path, member: str, destination: Path) -> Path:
    safe_name(member)
    with zipfile.ZipFile(archive) as bundle:
        info=bundle.getinfo(member)
        if Path(member).is_absolute() or ".." in Path(member).parts or info.is_dir(): raise ValueError("unsafe archive member")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary=destination.with_suffix(destination.suffix + ".tmp")
        with bundle.open(info) as source, temporary.open("wb") as target: shutil.copyfileobj(source, target, 1024 * 1024)
        temporary.replace(destination)
    return destination
