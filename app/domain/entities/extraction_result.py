from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Result returned by a firmware extraction backend."""

    firmware_path: Path
    extracted_path: Path
    filesystem_type: str
    architecture: str
    metadata: dict[str, str]
