from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppSettings:
    """Centralized settings for FLENS runtime behavior."""

    cve_database_path: Path
    report_template_dir: Path
    extraction_work_dir: Path


def default_settings() -> AppSettings:
    project_root = Path(__file__).resolve().parents[2]
    return AppSettings(
        cve_database_path=project_root / "app" / "infrastructure" / "data_sources" / "cve_db.json",
        report_template_dir=project_root / "app" / "presentation" / "reports" / "templates",
        extraction_work_dir=project_root / "sample_data" / "extracted",
    )
