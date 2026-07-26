import re
from functools import total_ordering


@total_ordering
class ComparableVersion:
    """Conservative comparator for numeric upstream and vendor-patch versions."""

    def __init__(self, value: str) -> None:
        if not re.fullmatch(r"\d+(?:[._]\d+)*(?:[a-z]+\d*)?(?:-r?\d+)?", value, re.I):
            raise ValueError("Unsupported version format")
        self.value = value
        parts = re.findall(r"\d+|[a-z]+", value.lower().replace("_", "."))
        self.key = tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ComparableVersion) and self.key == other.key

    def __lt__(self, other: object) -> bool:
        return isinstance(other, ComparableVersion) and self.key < other.key


def matches_range(version: str, expression: str) -> bool:
    current = ComparableVersion(version)
    for operator, target in re.findall(r"(>=|<=|!=|=|>|<)\s*([^\s,]+)", expression):
        candidate = ComparableVersion(target)
        matched = {
            ">=": current >= candidate,
            ">": current > candidate,
            "<=": current <= candidate,
            "<": current < candidate,
            "=": current == candidate,
            "!=": current != candidate,
        }[operator]
        if not matched:
            return False
    return True
