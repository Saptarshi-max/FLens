"""Focused tests for report-conversion configuration and non-browser control flow."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load_converter() -> ModuleType:
    script_path = Path(__file__).parents[2] / "tools" / "convert_reports_to_pdf.py"
    specification = importlib.util.spec_from_file_location("convert_reports_to_pdf", script_path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


converter = _load_converter()
ReportSpec = converter.ReportSpec


def test_configured_mapping_has_unique_existing_html_inputs_and_pdf_targets() -> None:
    root = Path(__file__).parents[2]

    reports = converter.validate_reports(converter.REPORTS)

    assert len(reports) == 11
    assert all((root / report.html_path).is_file() for report in reports)
    assert len({report.pdf_path for report in reports}) == len(reports)


def test_select_reports_filters_a_single_known_identifier() -> None:
    selected = converter.select_reports(converter.REPORTS, "archer-c7-v5")

    assert [report.identifier for report in selected] == ["archer-c7-v5"]
    with pytest.raises(ValueError, match="Unknown report ID"):
        converter.select_reports(converter.REPORTS, "unknown")


def test_duplicate_identifiers_and_targets_are_rejected() -> None:
    first = ReportSpec("same", "One", "one.bin", Path("one.html"), Path("one.pdf"))
    duplicate_id = ReportSpec("same", "Two", "two.bin", Path("two.html"), Path("two.pdf"))
    duplicate_target = ReportSpec("other", "Two", "two.bin", Path("two.html"), Path("one.pdf"))

    with pytest.raises(ValueError, match="identifiers"):
        converter.validate_reports((first, duplicate_id))
    with pytest.raises(ValueError, match="targets"):
        converter.validate_reports((first, duplicate_target))


def test_missing_input_is_reported_without_calling_renderer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = ReportSpec(
        "missing", "Missing", "missing.bin", Path("missing.html"), Path("report.pdf")
    )

    result = converter.convert_reports(
        tmp_path, (report,), overwrite=False, renderer=lambda _a, _b: None
    )

    assert result == 1
    assert "missing HTML input" in capsys.readouterr().out


def test_renderer_receives_repository_relative_output_and_overwrite_is_respected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    html_path = tmp_path / "input" / "report.html"
    html_path.parent.mkdir()
    html_path.write_text("<html><body>report</body></html>", encoding="utf-8")
    report = ReportSpec(
        "valid", "Valid", "valid.bin", Path("input/report.html"), Path("output/report.pdf")
    )
    calls: list[tuple[Path, Path]] = []

    def renderer(source: Path, target: Path) -> None:
        calls.append((source, target))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"%PDF-test")

    assert converter.convert_reports(tmp_path, (report,), overwrite=False, renderer=renderer) == 0
    assert calls == [(html_path, tmp_path / "output" / "report.pdf")]
    assert converter.convert_reports(tmp_path, (report,), overwrite=False, renderer=renderer) == 0
    assert len(calls) == 1
    assert "PDF already exists" in capsys.readouterr().out
    assert converter.convert_reports(tmp_path, (report,), overwrite=True, renderer=renderer) == 0
    assert len(calls) == 2
