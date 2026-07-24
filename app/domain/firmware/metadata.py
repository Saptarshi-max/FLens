from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FirmwareMetadata:
    """Normalized firmware metadata extracted during analysis."""

    architecture: str
    filesystem_type: str
    kernel_information: str
    vendor_information: str
