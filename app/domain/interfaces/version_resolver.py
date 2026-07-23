from abc import ABC, abstractmethod


class VersionResolver(ABC):
    """Resolve component versions through pluggable strategies."""

    @abstractmethod
    def resolve(self, component_name: str) -> str:
        """Return component version, or 'unknown' when unavailable."""
