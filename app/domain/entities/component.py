from dataclasses import dataclass, field

from app.domain.entities.evidence import Evidence


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
