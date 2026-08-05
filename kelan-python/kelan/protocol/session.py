"""
Session Manager — in-memory session and verdict store.
Bounded by maxlen deques; no database needed for operational state.
"""
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
import structlog

from ..ai.ollama_client import TrustVerdict, Verdict

log = structlog.get_logger()


@dataclass
class SessionRecord:
    session_id: str
    entity_id: str
    verdict: Verdict
    confidence: float
    reason: str
    created_at: float = field(default_factory=time.time)
    permit_token: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "entity_id": self.entity_id,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "created_at": self.created_at,
        }


class SessionManager:
    """
    Lightweight in-memory session store.
    Automatically expires oldest entries when capacity is exceeded.
    """

    def __init__(self, capacity: int = 5000):
        self._sessions: dict[str, SessionRecord] = {}
        self._order: deque[str] = deque(maxlen=capacity)
        self._capacity = capacity

    def store(
        self,
        session_id: str,
        entity_id: str,
        verdict: TrustVerdict,
    ) -> SessionRecord:
        """Store a session verdict and return the record.

        Eviction: deque(maxlen=capacity) auto-drops the oldest session_id
        when full. We then remove the evicted ID from _sessions to free
        memory. O(1) amortised — no loop needed.
        """
        token = str(uuid.uuid4()) if verdict.verdict != Verdict.DENY else None
        record = SessionRecord(
            session_id=session_id,
            entity_id=entity_id,
            verdict=verdict.verdict,
            confidence=verdict.confidence,
            reason=verdict.reason,
            permit_token=token,
        )
        self._sessions[session_id] = record

        # If at capacity, the deque will drop the oldest ID on append.
        # Capture it first so we can remove it from _sessions.
        evicted: Optional[str] = self._order[0] if len(self._order) >= self._capacity else None
        self._order.append(session_id)          # oldest auto-dropped if maxlen hit
        if evicted and evicted not in self._order:
            self._sessions.pop(evicted, None)   # free the dict entry too

        return record

    def get(self, session_id: str) -> Optional[SessionRecord]:
        return self._sessions.get(session_id)

    def recent_verdicts(self, limit: int = 100) -> list[dict]:
        """Return the most recent `limit` verdict records."""
        ids = list(self._order)[-limit:]
        return [self._sessions[sid].to_dict() for sid in reversed(ids)
                if sid in self._sessions]

    def count_by_verdict(self) -> dict[str, int]:
        counts: dict[str, int] = {"ALLOW": 0, "DENY": 0, "MONITOR": 0}
        for r in self._sessions.values():
            counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
        return counts

    def stats(self) -> dict:
        return {
            "total_sessions": len(self._sessions),
            "capacity": self._capacity,
            "by_verdict": self.count_by_verdict(),
        }
