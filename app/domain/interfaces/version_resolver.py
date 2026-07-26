from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from app.domain.entities.evidence import Evidence


@dataclass(frozen=True, slots=True)
class VersionResolution:
    version: str = "Unknown"
    evidence: tuple[Evidence, ...] = ()
    confidence: str = "LOW"


class VersionResolver(ABC):
    """Resolve component versions through pluggable strategies."""

    @abstractmethod
    def resolve(
        self, component_name: str, rootfs_path: Path, binary_paths: tuple[Path, ...]
    ) -> VersionResolution:
        """Return a version derived from the supplied filesystem evidence."""
