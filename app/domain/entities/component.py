from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Component:
    """A software component discovered in firmware."""

    name: str
    version: str
