from dataclasses import dataclass

from app.domain.entities.vulnerability import Vulnerability
from app.domain.value_objects.risk_score import RiskScore
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    """Configurable thresholds for classifying overall scan risk."""

    medium_min: int = 4
    high_min: int = 10
    critical_min: int = 20


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """Severity-to-score weights used during risk scoring."""

    critical: int = 10
    high: int = 7
    medium: int = 4
    low: int = 1


class RiskEngine:
    """Computes aggregate risk from vulnerability severities."""

    def __init__(
        self,
        thresholds: RiskThresholds | None = None,
        weights: RiskWeights | None = None,
    ) -> None:
        self._thresholds = thresholds or RiskThresholds()
        self._weights = weights or RiskWeights()

    def score(self, vulnerabilities: list[Vulnerability]) -> RiskScore:
        if not vulnerabilities:
            return RiskScore.LOW

        total = 0
        for vulnerability in vulnerabilities:
            total += self._weight_for(vulnerability.severity)

        if total >= self._thresholds.critical_min:
            return RiskScore.CRITICAL
        if total >= self._thresholds.high_min:
            return RiskScore.HIGH
        if total >= self._thresholds.medium_min:
            return RiskScore.MEDIUM
        return RiskScore.LOW

    def _weight_for(self, severity: str) -> int:
        severity_upper = severity.upper()
        if severity_upper == Severity.CRITICAL.value:
            return self._weights.critical
        if severity_upper == Severity.HIGH.value:
            return self._weights.high
        if severity_upper == Severity.MEDIUM.value:
            return self._weights.medium
        return self._weights.low
