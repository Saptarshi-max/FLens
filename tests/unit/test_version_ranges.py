import pytest

from app.infrastructure.versioning import matches_range


@pytest.mark.parametrize(
    ("version", "expression", "expected"),
    [
        ("1.1.1d", ">=1.1.1 <1.1.1k", True),
        ("1.1.1k", ">=1.1.1 <1.1.1k", False),
        ("1.36.1-2", ">=1.30 <1.40", True),
        ("2020.81", "!=2020.81", False),
    ],
)
def test_version_ranges(version: str, expression: str, expected: bool) -> None:
    assert matches_range(version, expression) is expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [("<1.23.0", True), ("<1.35", True), ("<=1.3.7", True), (">=1.36.1", False)],
)
def test_busybox_1_01_range_regression(expression: str, expected: bool) -> None:
    assert matches_range("1.01", expression) is expected
