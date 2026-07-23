from enum import StrEnum


class RiskScore(StrEnum):
    """Overall firmware risk classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
