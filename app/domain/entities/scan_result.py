from dataclasses import dataclass

from app.domain.entities.component import Component
from app.domain.entities.vulnerability import Vulnerability


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The immutable output of a firmware filesystem scan."""

    components: tuple[Component, ...]
    vulnerabilities: tuple[Vulnerability, ...]
    risk_score: str
