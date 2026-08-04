"""Database session helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class DatabaseSettings:
    url: str = "sqlite:///webosint.db"
    echo: bool = False


def create_session_factory(settings: DatabaseSettings) -> Any:
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
    except ImportError as exc:
        raise RuntimeError("SQLAlchemy is required for database support") from exc

    engine = create_engine(settings.url, echo=settings.echo, future=True)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
