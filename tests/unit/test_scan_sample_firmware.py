import csv
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def batch_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "scan_sample_firmware.py"
    spec = importlib.util.spec_from_file_location("scan_sample_firmware", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_discovery_and_collision_safe_names(batch_module, tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    for path in (tmp_path / "a/router.bin", tmp_path / "b/router.BIN"):
        path.write_bytes(b"x")
    (tmp_path / "a/ignored.txt").write_text("x")
    discovered = batch_module.discover_firmware(tmp_path)
    assert [path.relative_to(tmp_path).as_posix() for path in discovered] == [
        "a/router.bin",
        "b/router.BIN",
    ]
    assert batch_module.output_name(discovered[0], tmp_path) != batch_module.output_name(
        discovered[1], tmp_path
    )
    assert batch_module.discover_firmware(tmp_path / "missing") == []


def test_summary_serializers_are_deterministic(batch_module, tmp_path: Path) -> None:
    results = [
        {
            "source_firmware": "z.bin",
            "status": "extraction_failed",
            "stage": "extraction",
            "reason": "x",
        },
        {"source_firmware": "a.bin", "status": "succeeded"},
    ]
    batch_module.write_batch_summary(tmp_path, results)
    payload = json.loads((tmp_path / "batch-summary.json").read_text())
    rows = list(csv.DictReader((tmp_path / "batch-summary.csv").open()))
    assert [item["source_firmware"] for item in payload["results"]] == ["a.bin", "z.bin"]
    assert len(rows) == payload["total_firmware_files"] == 2
    assert payload["succeeded"] == payload["extraction_failed"] == 1
    assert (tmp_path / "README.md").is_file()


def test_scan_all_isolates_failures_and_writes_success_artifacts(
    batch_module, monkeypatch, tmp_path: Path
) -> None:
    from app.infrastructure.extraction.errors import ExtractionError

    input_dir = tmp_path / "input"
    input_dir.mkdir()
    for name in ("a.bin", "b.bin", "c.bin"):
        (input_dir / name).write_bytes(b"x")

    class Analysis:
        def execute(self, firmware: Path):
            if firmware.name == "a.bin":
                raise ExtractionError("empty")
            if firmware.name == "b.bin":
                raise OSError("read error")
            return SimpleNamespace(
                scan_result=SimpleNamespace(
                    components=(object(),),
                    vulnerabilities=(),
                    inventory_statistics=None,
                    identity_statistics=None,
                )
            )

    class Report:
        def generate(self, _result, path: Path) -> Path:
            path.write_text("html")
            return path

    class Sbom:
        def execute(self, _result):
            document = SimpleNamespace(content={"ok": True})
            return SimpleNamespace(cyclonedx=document, spdx=document)

    class Container:
        def __init__(self, *_args):
            pass

        def build_firmware_analysis_use_case(self):
            return Analysis()

        def build_report_generator(self):
            return Report()

        def build_sbom_generator(self):
            return object()

    monkeypatch.setattr(batch_module, "Container", Container)
    monkeypatch.setattr(batch_module, "GenerateSBOMUseCase", lambda _generator: Sbom())
    results = batch_module.scan_all(input_dir, tmp_path / "out", work_dir=tmp_path / "work")
    assert [item["status"] for item in results] == ["extraction_failed", "scan_failed", "succeeded"]
    assert "artefacts" not in results[0] and "artefacts" not in results[1]
    assert all(Path(path).is_file() for path in results[2]["artefacts"].values())


def test_overwrite_false_skips_existing_output(batch_module, tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    firmware = source / "router.bin"
    firmware.write_bytes(b"x")
    output = tmp_path / "output"
    existing = output / batch_module.output_name(firmware, source)
    existing.mkdir(parents=True)
    (existing / "scan-summary.json").write_text("{}")
    results = batch_module.scan_all(source, output, overwrite=False)
    assert results[0]["status"] == "skipped"
