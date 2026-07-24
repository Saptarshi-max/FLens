from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.database.models import Base


def create_database_engine(database_path: Path) -> Engine:
    """Create a SQLite engine and ensure tables are initialized."""

    engine = create_engine(f"sqlite:///{database_path}", future=True)
    Base.metadata.create_all(engine)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a reusable SQLAlchemy session factory."""

    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
