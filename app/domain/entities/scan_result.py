from dataclasses import dataclass

from app.domain.entities.component import Component
from app.domain.entities.identity_statistics import IdentityStatistics
from app.domain.entities.inventory import InventoryStatistics
from app.domain.entities.vulnerability import Vulnerability


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The immutable output of a firmware filesystem scan."""

    components: tuple[Component, ...]
    vulnerabilities: tuple[Vulnerability, ...]
    risk_score: str
    inventory_statistics: InventoryStatistics | None = None
    inventory_diagnostics: tuple[tuple[str, str, str], ...] = ()
    identity_statistics: IdentityStatistics | None = None
