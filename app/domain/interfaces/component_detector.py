from abc import ABC, abstractmethod
from pathlib import Path

from app.domain.entities.component import Component


class ComponentDetector(ABC):
    """Detect software components from an extracted root filesystem."""

    @abstractmethod
    def detect(self, rootfs_path: Path) -> list[Component]:
        """Return discovered components from a rootfs path."""
