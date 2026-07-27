"""Single deterministic CPE source-selection policy."""

from dataclasses import dataclass

from app.domain.entities.component import Component


@dataclass(frozen=True, slots=True)
class CpeSelection:
    candidates: tuple[str, ...]
    source: str


def select_cpe_candidates(component: Component) -> CpeSelection:
    governed = component.identity_resolution.cpe_candidates if component.identity_resolution else ()
    legacy = component.cpe_candidates + ((component.cpe,) if component.cpe else ())
    candidates = tuple(sorted({candidate for candidate in (governed or legacy) if candidate}))
    return CpeSelection(candidates, "governed" if governed else "legacy" if candidates else "none")
