import re
from dataclasses import dataclass
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


@dataclass(frozen=True, slots=True)
class ELFAnalysis:
    """Static ELF analysis result for component fingerprinting."""

    architecture: str
    binary_type: str
    strings: tuple[str, ...]
    inferred_component: str | None


class ELFAnalyzer:
    """Analyze ELF binaries for architecture and component fingerprints."""

    _component_markers = {
        "openssl": "openssl",
        "busybox": "busybox",
        "dropbear": "dropbear",
    }

    def analyze(self, binary_path: Path) -> ELFAnalysis | None:
        try:
            with binary_path.open("rb") as file_handle:
                magic = file_handle.read(4)
                if magic != b"\x7fELF":
                    return None
                file_handle.seek(0)
                elf = ELFFile(file_handle)
                architecture = elf["e_machine"]
                binary_type = elf["e_type"]

            strings = self._extract_strings_streaming(binary_path)
            inferred_component = self._infer_component(strings)
            return ELFAnalysis(
                architecture=str(architecture),
                binary_type=str(binary_type),
                strings=strings,
                inferred_component=inferred_component,
            )
        except (ELFError, OSError):
            return None

    def _extract_strings_streaming(self, binary_path: Path) -> tuple[str, ...]:
        pattern = re.compile(rb"[ -~]{4,}")
        found: list[str] = []

        with binary_path.open("rb") as file_handle:
            while True:
                chunk = file_handle.read(64 * 1024)
                if not chunk:
                    break
                for match in pattern.findall(chunk):
                    found.append(match.decode("ascii", errors="ignore"))
                if len(found) >= 200:
                    break

        return tuple(found)

    def _infer_component(self, strings: tuple[str, ...]) -> str | None:
        joined = "\n".join(strings).lower()
        for marker, component in self._component_markers.items():
            if marker in joined:
                return component
        return None
