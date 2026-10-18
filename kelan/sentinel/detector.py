from __future__ import annotations
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
import structlog
from ..db.database import save_anomaly

log = structlog.get_logger()


@dataclass
class AnomalyEvent:
    source:   str
    kind:     str
    severity: float
    details:  dict
    ts:       float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "kind": self.kind,
                "severity": self.severity, "details": self.details,
                "ts": round(self.ts, 2)}


class SentinelDetector:

    def __init__(self) -> None:
        self._enroll:  dict[str, deque]  = defaultdict(lambda: deque(maxlen=200))
        self._connect: dict[str, deque]  = defaultdict(lambda: deque(maxlen=1000))
        self._auth_fail: dict[str, list] = defaultdict(list)
        self._ports:   dict[str, set]    = defaultdict(set)
        self._events:  deque             = deque(maxlen=2000)

    def analyze(self, entity_id: str, intent: str, source_ip: str = "") -> dict[str, Any]:
        now = time.time()
        key = source_ip or entity_id
        out: dict = {}

        # ── Enrollment burst (sybil) ──────────────────────────
        if "ENROL" in intent.upper():
            q = self._enroll[key]
            q.append(now)
            burst = [t for t in q if now - t < 5.0]
            if len(burst) > 10:
                out |= {
                    "rapid_enrollment_burst":    True,
                    "enrollment_count_from_ip":  len(burst),
                    "enrollment_window_seconds": 5,
                    "pattern":                   "sybil_attack",
                }
                self._emit_and_save(AnomalyEvent(
                    key, "sybil_attack", 0.90,
                    {"count": len(burst), "window": "5s"}
                ))

        # ── Connection rate (flood) 
        q2 = self._connect[key]
        q2.append(now)
        rate = len([t for t in q2 if now - t < 1.0])
        if rate > 50:
            out |= {
                "syn_rate_per_second": rate,
                "threshold":           50,
                "pattern":             "flood_attack",
            }
            self._emit_and_save(AnomalyEvent(
                key, "flood", 0.95, {"rate": rate}
            ))

        # ── Auth failures (brute force) 
        if "AUTH" in intent.upper():
            fails = self._auth_fail[key]
            fails.append(now)
            recent = [t for t in fails if now - t < 60]
            if len(recent) > 20:
                out |= {
                    "failed_auth_attempts": len(recent),
                    "window_seconds":       60,
                    "pattern":              "brute_force",
                }
                self._emit_and_save(AnomalyEvent(
                    key, "brute_force", 0.85,
                    {"count": len(recent)}
                ))

        return out

    def record_port_probe(self, source_ip: str, port: int) -> None:
        self._ports[source_ip].add(port)
        n = len(self._ports[source_ip])
        thresholds = {100: 0.6, 500: 0.75, 1000: 0.85, 5000: 0.95}
        for threshold, severity in thresholds.items():
            if n == threshold:
                self._emit_and_save(AnomalyEvent(
                    source_ip, "port_scan", severity,
                    {"ports_probed": n, "pattern": "reconnaissance"}
                ))
                log.warning("port_scan", src=source_ip, ports=n)

    def _emit_and_save(self, event: AnomalyEvent) -> None:
        self._events.append(event)
        log.warning("sentinel", kind=event.kind,
                    severity=event.severity, src=event.source)
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(
                    save_anomaly(event.source, event.kind,
                                 event.severity, event.details)
                )
        except Exception:
            pass

    def recent(self, n: int = 50) -> list[dict[str, Any]]:
        return [e.to_dict() for e in list(self._events)[-n:]]
