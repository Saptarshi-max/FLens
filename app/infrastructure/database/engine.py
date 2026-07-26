from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.database.models import Base


def create_database_engine(database_path: Path) -> Engine:
    """Create a SQLite engine and ensure tables are initialized."""

    engine = create_engine(f"sqlite:///{database_path}", future=True)
    Base.metadata.create_all(engine)
    _migrate_evidence_columns(engine)
    return engine


def _migrate_evidence_columns(engine: Engine) -> None:
    """Apply the additive SQLite migration needed by the evidence model."""
    additions = {
        "component": (
            ("confidence", "VARCHAR(16) NOT NULL DEFAULT 'LOW'"),
            ("evidence", "TEXT NOT NULL DEFAULT '[]'"),
        ),
        "vulnerability": (
            ("component_name", "VARCHAR(255) NOT NULL DEFAULT 'Unknown'"),
            ("component_version", "VARCHAR(64) NOT NULL DEFAULT 'Unknown'"),
            ("confidence", "VARCHAR(16) NOT NULL DEFAULT 'LOW'"),
            ("evidence", "TEXT NOT NULL DEFAULT '[]'"),
        ),
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in columns:
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a reusable SQLAlchemy session factory."""

    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
