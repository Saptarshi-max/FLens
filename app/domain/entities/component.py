from dataclasses import dataclass, field

from app.domain.entities.evidence import Evidence
from app.domain.entities.identity_resolution import IdentityResolution


@dataclass(frozen=True, slots=True)
class Component:
    """A software component discovered in firmware."""

    name: str
    version: str = "Unknown"
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    confidence: str = "LOW"
    cpe: str | None = None
    cpe_candidates: tuple[str, ...] = field(default_factory=tuple)
    cpe_confidence: str = "LOW"
    component_type: str = "application"
    architecture: str = "Unknown"
    dependencies: tuple[str, ...] = field(default_factory=tuple)
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    identity_resolution: IdentityResolution | None = None
    cpe_source: str = "none"
