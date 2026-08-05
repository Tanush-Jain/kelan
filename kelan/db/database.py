"""Async database engine and session factory."""
import json
import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from .models import Base, VerdictLog, AnomalyLog
from ..config import get_settings

_engine = None
_session_factory = None


async def init_db():
    global _engine, _session_factory
    os.makedirs("data", exist_ok=True)
    cfg = get_settings()
    
    # Ensure the connection string is: "sqlite+aiosqlite:///data/aitp.db"
    db_url = cfg.database_url
    if not db_url or ("sqlite" in db_url and ":memory:" not in db_url):
        db_url = "sqlite+aiosqlite:///data/aitp.db"

    _engine = create_async_engine(
        db_url,
        echo=cfg.debug,
        pool_pre_ping=True,
    )
    _session_factory = async_sessionmaker(
        _engine, expire_on_commit=False, class_=AsyncSession
    )
    try:
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            from sqlalchemy import text
            
            # Self-healing migrations for Entity columns
            entities_cols = [
                ("name", "VARCHAR"),
                ("public_key", "TEXT"),
                ("enrollment_count", "INTEGER DEFAULT 0"),
                ("is_banned", "BOOLEAN DEFAULT 0"),
                ("last_seen", "FLOAT"),
                ("created_at", "FLOAT"),
                ("org_id", "VARCHAR"),
                ("entity_type", "VARCHAR"),
                ("department", "VARCHAR"),
                ("clearance_level", "INTEGER DEFAULT 0"),
                ("allowed_intents", "TEXT DEFAULT '[]'"),
                ("trust_score_avg", "FLOAT DEFAULT 128.0"),
                ("session_count", "INTEGER DEFAULT 0"),
                ("blocked_count", "INTEGER DEFAULT 0"),
                ("quarantined", "INTEGER DEFAULT 0"),
                ("enrolled_at", "FLOAT"),
            ]
            for col_name, col_type in entities_cols:
                try:
                    await conn.execute(text(f"ALTER TABLE entities ADD COLUMN {col_name} {col_type};"))
                except Exception:
                    pass
            
            # Self-healing migrations for Session columns
            sessions_cols = [
                ("entity_id", "VARCHAR"),
                ("phase", "INTEGER DEFAULT 0"),
                ("verdict", "VARCHAR"),
                ("confidence", "FLOAT DEFAULT 0.0"),
                ("reason", "TEXT"),
                ("intent", "VARCHAR"),
                ("anomalies", "TEXT DEFAULT '{}'"),
                ("created_at", "FLOAT"),
                ("updated_at", "FLOAT"),
                ("org_id", "VARCHAR"),
                ("source_entity_id", "VARCHAR"),
                ("dest_entity_id", "VARCHAR"),
                ("trust_score", "INTEGER DEFAULT 128"),
                ("ai_reasoning", "TEXT"),
                ("ai_latency_ms", "FLOAT"),
                ("status", "VARCHAR DEFAULT 'Active'"),
                ("bytes_tx", "INTEGER DEFAULT 0"),
                ("bytes_rx", "INTEGER DEFAULT 0"),
                ("anomaly_flags", "TEXT DEFAULT ''"),
                ("started_at", "FLOAT"),
                ("ended_at", "FLOAT"),
                ("close_reason", "VARCHAR"),
            ]
            for col_name, col_type in sessions_cols:
                try:
                    await conn.execute(text(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_type};"))
                except Exception:
                    pass

            try:
                await conn.execute(text("CREATE VIEW IF NOT EXISTS verdicts AS SELECT * FROM verdict_log;"))
            except Exception:
                pass
            try:
                await conn.execute(text("CREATE VIEW IF NOT EXISTS anomalies AS SELECT * FROM anomaly_log;"))
            except Exception:
                pass
            try:
                await conn.execute(text("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, timestamp REAL);"))
            except Exception:
                pass
    except Exception as e:
        raise RuntimeError(f"Failed to initialize database: {e}") from e


def get_session() -> AsyncSession:
    assert _session_factory is not None, (
        "Database not initialised. "
        "Call await init_db() first."
    )
    return _session_factory()


async def save_verdict(session_id: str, entity_id: str,
                       verdict: str, confidence: float,
                       reason: str, latency_ms: float,
                       anomalies: dict):
    async with get_session() as s:
        s.add(VerdictLog(
            session_id   = session_id,
            entity_id    = entity_id,
            verdict      = verdict,
            confidence   = confidence,
            reason       = reason,
            latency_ms   = latency_ms,
            anomaly_json = json.dumps(anomalies),
        ))
        await s.commit()


async def save_anomaly(source: str, kind: str,
                       severity: float, details: dict):
    async with get_session() as s:
        s.add(AnomalyLog(
            source       = source,
            kind         = kind,
            severity     = severity,
            details_json = json.dumps(details),
        ))
        await s.commit()


async def fetch_verdicts(limit: int = 100) -> list[dict]:
    from sqlalchemy import select, desc
    async with get_session() as s:
        rows = await s.execute(
            select(VerdictLog)
            .order_by(desc(VerdictLog.created_at))
            .limit(limit)
        )
        return [
            {
                "id":          r.id,
                "entity_id":   r.entity_id,
                "session_id":  r.session_id,
                "verdict":     r.verdict,
                "confidence":  r.confidence,
                "reason":      r.reason,
                "latency_ms":  r.latency_ms,
                "created_at":  r.created_at,
            }
            for r in rows.scalars().all()
        ]


async def fetch_anomalies(limit: int = 50) -> list[dict]:
    from sqlalchemy import select, desc
    async with get_session() as s:
        rows = await s.execute(
            select(AnomalyLog)
            .order_by(desc(AnomalyLog.created_at))
            .limit(limit)
        )
        return [
            {
                "id":        r.id,
                "source":    r.source,
                "kind":      r.kind,
                "severity":  r.severity,
                "details":   json.loads(str(r.details_json or "{}")),
                "created_at":r.created_at,
            }
            for r in rows.scalars().all()
        ]
