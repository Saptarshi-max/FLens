"""Evidence-backed canonical product identity decisions."""

from dataclasses import dataclass

from app.domain.entities.evidence import Evidence


@dataclass(frozen=True, slots=True)
class IdentityResolution:
    canonical_product: str | None
    canonical_vendor: str | None
    cpe_candidates: tuple[str, ...]
    confidence: str
    rule_id: str
    evidence: tuple[Evidence, ...]
    resolution_status: str
