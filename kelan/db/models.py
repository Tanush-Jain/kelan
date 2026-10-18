"""SQLAlchemy async ORM models."""
import time
import uuid
from sqlalchemy import Column, String, Float, Integer, Boolean, Text, Index
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())

def _now() -> float:
    return time.time()


class Session(Base):
    __tablename__ = "sessions"
    id          = Column(String, primary_key=True, default=_uuid)
    entity_id   = Column(String, nullable=False, index=True)
    phase       = Column(Integer, default=0)
    verdict     = Column(String)
    confidence  = Column(Float, default=0.0)
    reason      = Column(Text)
    intent      = Column(String)
    anomalies   = Column(Text, default="{}")
    created_at  = Column(Float, default=_now)
    updated_at  = Column(Float, default=_now)
    
    org_id           = Column(String, nullable=True)
    source_entity_id = Column(String, nullable=True)
    dest_entity_id   = Column(String, nullable=True)
    trust_score      = Column(Integer, default=128)
    ai_reasoning     = Column(Text, nullable=True)
    ai_latency_ms    = Column(Float, nullable=True)
    status           = Column(String, default="Active")
    bytes_tx         = Column(Integer, default=0)
    bytes_rx         = Column(Integer, default=0)
    anomaly_flags    = Column(Text, default="")
    started_at       = Column(Float, default=_now)
    ended_at         = Column(Float, nullable=True)
    close_reason     = Column(String, nullable=True)


class Entity(Base):
    __tablename__ = "entities"
    id               = Column(String, primary_key=True, default=_uuid)
    name             = Column(String)
    public_key       = Column(Text)
    enrollment_count = Column(Integer, default=0)
    is_banned        = Column(Boolean, default=False)
    last_seen        = Column(Float)
    created_at       = Column(Float, default=_now)
    
    org_id           = Column(String, nullable=True)
    entity_type      = Column(String, nullable=True)
    department       = Column(String, nullable=True)
    clearance_level  = Column(Integer, default=0)
    allowed_intents  = Column(Text, default="[]")
    trust_score_avg  = Column(Float, default=128.0)
    session_count    = Column(Integer, default=0)
    blocked_count    = Column(Integer, default=0)
    quarantined      = Column(Integer, default=0)
    enrolled_at      = Column(Float, default=_now)


class VerdictLog(Base):
    __tablename__ = "verdict_log"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    entity_id    = Column(String, nullable=False, index=True)
    session_id   = Column(String)
    verdict      = Column(String, nullable=False)
    confidence   = Column(Float, default=0.0)
    reason       = Column(Text)
    latency_ms   = Column(Float, default=0.0)
    anomaly_json = Column(Text, default="{}")
    created_at   = Column(Float, default=_now, index=True)

    __table_args__ = (
        Index("ix_verdict_log_time", "created_at"),
        Index("ix_verdict_log_entity", "entity_id"),
    )


class AnomalyLog(Base):
    __tablename__ = "anomaly_log"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    source       = Column(String, index=True)
    kind         = Column(String, nullable=False)
    severity     = Column(Float, nullable=False)
    details_json = Column(Text, default="{}")
    created_at   = Column(Float, default=_now, index=True)
