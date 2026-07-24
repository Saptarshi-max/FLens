from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class SBOMFormat(StrEnum):
    """Supported SBOM export formats."""

    CYCLONEDX_JSON = "cyclonedx-json"
    SPDX_JSON = "spdx-json"


@dataclass(frozen=True, slots=True)
class SBOMComponent:
    """A software component represented in an SBOM document."""

    name: str
    version: str
    purl: str | None = None


@dataclass(frozen=True, slots=True)
class SBOMDocument:
    """Generated SBOM output in a specific format."""

    format: SBOMFormat
    components: tuple[SBOMComponent, ...]
    content: dict[str, Any]
