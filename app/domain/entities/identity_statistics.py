"""Validated scan-level identity-resolution accounting."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdentityStatistics:
    resolved: int = 0
    excluded: int = 0
    ambiguous: int = 0
    unsupported: int = 0
    insufficient_evidence: int = 0
    governed_cpe_components: int = 0
    legacy_cpe_components: int = 0
    no_cpe_components: int = 0

    def __post_init__(self) -> None:
        if min(self.status_total, self.cpe_source_total) < 0:
            raise ValueError("identity statistics cannot be negative")
        if self.status_total != self.cpe_source_total:
            raise ValueError("identity status and CPE source totals must reconcile")

    @property
    def status_total(self) -> int:
        return (
            self.resolved
            + self.excluded
            + self.ambiguous
            + self.unsupported
            + self.insufficient_evidence
        )

    @property
    def cpe_source_total(self) -> int:
        return self.governed_cpe_components + self.legacy_cpe_components + self.no_cpe_components
