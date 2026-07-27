import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "benchmark_inventory.py"
_SPEC = importlib.util.spec_from_file_location("benchmark_inventory", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_csv_rows = _MODULE._csv_rows
_readme = _MODULE._readme


def _measurement() -> dict[str, object]:
    return {
        "firmware_image": "sample_data/firmware/openwrt/example.bin",
        "extraction_success": True,
        "extracted_rootfs": "sample_data/extracted/example/squashfs-root",
        "package_database_types": ["opkg"],
        "architecture_observations": ["EM_MIPS"],
        "top_detected_components": ["busybox"],
        "scan_duration_seconds": 0.25,
        "legacy_component_count": None,
        "statistics": {
            "package_records_discovered": 2,
            "elf_files_examined": 3,
            "raw_components_discovered": 4,
            "merged_components": 3,
            "components_with_known_versions": 2,
            "components_with_unknown_versions": 1,
            "components_with_cpe_candidates": 1,
        },
    }


def test_benchmark_csv_rows_serialise_statistics_and_lists() -> None:
    row = _csv_rows([_measurement()])[0]

    assert row["package_records_discovered"] == 2
    assert row["package_database_types"] == "opkg"
    assert row["architecture_observations"] == "EM_MIPS"


def test_benchmark_readme_is_deterministic() -> None:
    measurements = [_measurement()]

    first = _readme(measurements)

    assert first == _readme(measurements)
    assert "example.bin" in first
    assert "| 4 | 3 | 2 | 1 | 1 | 0.25 |" in first
