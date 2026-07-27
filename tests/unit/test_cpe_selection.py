import pytest

from app.domain.entities.component import Component
from app.domain.entities.identity_resolution import IdentityResolution
from app.domain.entities.identity_statistics import IdentityStatistics
from app.domain.services.cpe_selection import select_cpe_candidates


def test_governed_precedence_and_legacy_fallback_are_deterministic() -> None:
    identity = IdentityResolution(
        None, None, ("cpe:z", "cpe:a", "cpe:a"), "HIGH", "rule", (), "resolved"
    )
    governed = Component("x", cpe_candidates=("legacy",), identity_resolution=identity)
    assert select_cpe_candidates(governed).candidates == ("cpe:a", "cpe:z")
    assert select_cpe_candidates(governed).source == "governed"
    legacy = Component("x", cpe="c", cpe_candidates=("b", "a", "", "a"))
    assert select_cpe_candidates(legacy).candidates == ("a", "b", "c")
    assert select_cpe_candidates(Component("x")).source == "none"


def test_singular_legacy_cpe_reaches_vulnerability_correlation() -> None:
    assert select_cpe_candidates(Component("busybox", cpe="cpe:2.3:a:busybox:busybox")) == (
        select_cpe_candidates(Component("busybox", cpe="cpe:2.3:a:busybox:busybox"))
    )


def test_identity_statistics_reconcile() -> None:
    stats = IdentityStatistics(
        resolved=1, excluded=1, governed_cpe_components=1, no_cpe_components=1
    )
    assert stats.status_total == stats.cpe_source_total == 2
    with pytest.raises(ValueError):
        IdentityStatistics(resolved=1, governed_cpe_components=0)
