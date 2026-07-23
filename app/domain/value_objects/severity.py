from enum import StrEnum


class Severity(StrEnum):
    """Supported vulnerability severities."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
