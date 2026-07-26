from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Evidence:
    """A reproducible fact used to identify a component or finding."""

    source: str
    path: str
    detail: str
