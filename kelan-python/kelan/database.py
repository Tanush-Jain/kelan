"""
Kelan Security — Async Database Layer (FIX 2)
SQLAlchemy async sessions with guaranteed cleanup.

FIX 2 — Session leak:
  Every session is closed in a `finally` block via the get_db()
  async context manager. Exceptions trigger rollback before close.
  Connection pool can never be exhausted by orphaned sessions.

Usage in route handlers:
    async with get_db() as db:
        result = await db.execute(select(MyModel))
        # commit is automatic on clean exit
        # rollback is automatic on exception
"""
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import structlog
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.sql import func

log = structlog.get_logger()


# ── ORM Base ──────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Models ────────────────────────────────────────────────────────────────────

class SessionRecord(Base):
    """Persisted record of every trust evaluation verdict."""
    __tablename__ = "sessions"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    session_id  = Column(String(64), unique=True, nullable=False, index=True)
    entity_id   = Column(String(128), nullable=False, index=True)
    verdict     = Column(String(16), nullable=False)   # ALLOW / DENY / MONITOR
    confidence  = Column(Float, nullable=False)
    reason      = Column(String(200), nullable=False)
    source_ip   = Column(String(45), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


class AnomalyEvent(Base):
    """Persisted anomaly events from the Sentinel engine."""
    __tablename__ = "anomaly_events"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    entity_id    = Column(String(128), nullable=True, index=True)
    anomaly_type = Column(String(64), nullable=False)
    severity     = Column(Float, nullable=False)
    details      = Column(Text, nullable=True)   # JSON string
    created_at   = Column(DateTime(timezone=True), server_default=func.now())


# ── Engine + session factory (module-level singletons) ───────────────────────

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker] = None


async def init_db() -> None:
    """
    Initialise the async engine and create all tables.
    Call once at application startup (inside lifespan).

    Pool settings:
      pool_size=5      — baseline connections kept open
      max_overflow=10  — burst connections (released after use)
      pool_pre_ping    — discard stale connections before use
      pool_recycle=1800 — recycle connections every 30 min
    """
    global _engine, _session_factory

    db_url = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./kelan.db",
    )

    # SQLite doesn't support pool_size / max_overflow — strip for SQLite
    kwargs: dict = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "echo": False,
    }
    if not db_url.startswith("sqlite"):
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 10

    _engine = create_async_engine(db_url, **kwargs)

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,   # objects stay usable after commit
    )

    # Create tables (idempotent — safe to call on every startup)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    log.info("database_ready", url=db_url.split("///")[0])   # log scheme only


async def close_db() -> None:
    """Dispose the engine and release all pooled connections. Call at shutdown."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        log.info("database_closed")


# ── FIX 2: get_db() — guaranteed session cleanup ─────────────────────────────

@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that yields a database session.

    FIX 2 — Session leak fix:
      - commit() called automatically on clean exit
      - rollback() called automatically on any exception
      - close() called in `finally` — ALWAYS runs, even on exception

    Usage:
        async with get_db() as db:
            result = await db.execute(select(SessionRecord))
            rows = result.scalars().all()
            # no explicit commit needed — happens on exit
    """
    if _session_factory is None:
        raise RuntimeError(
            "Database not initialised. Call `await init_db()` first."
        )

    session: AsyncSession = _session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        # Always runs — sessions can never be orphaned
        await session.close()
