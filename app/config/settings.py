import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppSettings:
    """Centralized settings for FLENS runtime behavior."""

    cve_database_path: Path
    report_template_dir: Path
    repository_url: str | None
    extraction_work_dir: Path
    database_path: Path
    upload_work_dir: Path
    feeds: tuple[str, ...] = ("json",)
    offline_mode: bool = True
    feed_refresh_interval: int = 86400


def default_settings() -> AppSettings:
    project_root = Path(__file__).resolve().parents[2]
    repository_url = os.getenv("FLENS_REPOSITORY_URL")
    return AppSettings(
        cve_database_path=project_root / "app" / "infrastructure" / "data_sources" / "cve_db.json",
        report_template_dir=project_root / "app" / "presentation" / "reports" / "templates",
        repository_url=repository_url.rstrip("/") if repository_url else None,
        extraction_work_dir=project_root / "sample_data" / "extracted",
        database_path=project_root / "flens.db",
        upload_work_dir=project_root / "sample_data" / "uploads",
        feeds=tuple(
            item.strip() for item in os.getenv("FLENS_FEEDS", "json").split(",") if item.strip()
        ),
        offline_mode=os.getenv("FLENS_OFFLINE_MODE", "true").lower() != "false",
        feed_refresh_interval=int(os.getenv("FLENS_FEED_REFRESH_INTERVAL", "86400")),
    )
