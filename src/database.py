from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
from src.config.settings import settings

from .models.base import Base
import logging

logger = logging.getLogger(__name__)


def _get_engine():
    db_url = settings.database_url

    if db_url.startswith("sqlite"):
        # SQLite needs special handling, esp. for tests (memory DB)
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False},  # for SQLite threading
            poolclass=StaticPool if ":memory:" in db_url else None,
            echo=settings.environment.lower() == "development",
        )
    else:
        # Assume PostgreSQL, MySQL, etc.
        return create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            echo=settings.environment.lower() == "development",
        )


# Create engine + session factory
engine = _get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


@contextmanager
def get_db_session():
    """Context manager for database sessions."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error: {e}")
        raise
    finally:
        session.close()


# FastAPI dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
