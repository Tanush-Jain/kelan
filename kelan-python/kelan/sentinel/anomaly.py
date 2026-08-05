"""
Sentinel Anomaly Detection Engine.
Stateful, in-memory detection for:
  - SYN / UDP floods (connection rate tracking)
  - Sybil attacks (rapid enrollment bursts from one IP/entity)
  - Port scans (reconnaissance tracking)
  - Brute-force auth (failed attempt tracking)

All state is bounded using deque(maxlen=N) — no unbounded memory growth.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional
import structlog

log = structlog.get_logger()


@dataclass
class AnomalyEvent:
    entity_id: Optional[str]
    anomaly_type: str
    severity: float          # 0.0 – 1.0
    details: dict
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class SentinelEngine:
    """
    Lightweight real-time anomaly detector.
    Call `analyze()` on every session to get an anomaly dict.
    Empty dict → clean session.
    """

    # Thresholds
    ENROLL_BURST_LIMIT = 10     # max enrollments from one key in 5 s
    ENROLL_BURST_WINDOW = 5.0   # seconds
    CONN_FLOOD_LIMIT = 50       # max connections from one key per second
    CONN_FLOOD_WINDOW = 1.0     # seconds
    PORT_SCAN_LIMIT = 100       # unique ports before flagging as scan
    BRUTE_FORCE_LIMIT = 20      # failed auth attempts before flag

    def __init__(self) -> None:
        # Per-key sliding windows
        self._enrollments: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._connections: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self._ports: dict[str, set] = defaultdict(set)
        self._failed_auth: dict[str, int] = defaultdict(int)

        # Global event log (bounded)
        self._events: deque = deque(maxlen=1000)

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(
        self,
        entity_id: str,
        intent: str,
        source_ip: str = "",
    ) -> dict:
        """
        Analyze a session and return an anomaly dict.
        Empty → clean. Non-empty → pass to Ollama for evaluation.
        """
        now = time.monotonic()
        key = source_ip or entity_id
        anomalies: dict = {}

        # ── Enrollment burst (Sybil detection) ─────────────────
        if intent.upper() in ("INIT_ENROL", "ENROLL", "ENROL"):
            self._enrollments[key].append(now)
            burst = [t for t in self._enrollments[key]
                     if now - t < self.ENROLL_BURST_WINDOW]
            if len(burst) > self.ENROLL_BURST_LIMIT:
                anomalies.update({
                    "rapid_enrollment_burst": True,
                    "enrollment_count_from_ip": len(burst),
                    "enrollment_window_seconds": self.ENROLL_BURST_WINDOW,
                    "pattern": "sybil_attack",
                })
                self._emit(AnomalyEvent(
                    entity_id=entity_id,
                    anomaly_type="sybil_attack",
                    severity=0.90,
                    details={"count": len(burst), "key": key,
                             "window_s": self.ENROLL_BURST_WINDOW},
                ))

        # ── Connection flood ────────────────────────────────────
        self._connections[key].append(now)
        flood = [t for t in self._connections[key]
                 if now - t < self.CONN_FLOOD_WINDOW]
        if len(flood) > self.CONN_FLOOD_LIMIT:
            anomalies.update({
                "syn_rate_per_second": len(flood),
                "syn_rate_threshold": self.CONN_FLOOD_LIMIT,
                "pattern": "flood_attack",
            })
            self._emit(AnomalyEvent(
                entity_id=entity_id,
                anomaly_type="connection_flood",
                severity=0.95,
                details={"rate_per_sec": len(flood), "key": key},
            ))

        return anomalies

    def record_port_probe(self, source_ip: str, port: int) -> None:
        """Record a single port probe from a source IP."""
        self._ports[source_ip].add(port)
        count = len(self._ports[source_ip])
        if count == self.PORT_SCAN_LIMIT + 1:   # emit once at threshold
            self._emit(AnomalyEvent(
                entity_id=None,
                anomaly_type="port_scan",
                severity=0.85,
                details={
                    "source_ip": source_ip,
                    "ports_probed": count,
                    "pattern": "reconnaissance",
                },
            ))

    def record_failed_auth(self, entity_id: str) -> dict:
        """Record a failed authentication attempt; returns anomaly if threshold hit."""
        self._failed_auth[entity_id] += 1
        count = self._failed_auth[entity_id]
        if count > self.BRUTE_FORCE_LIMIT:
            event = AnomalyEvent(
                entity_id=entity_id,
                anomaly_type="brute_force",
                severity=0.88,
                details={"failed_attempts": count},
            )
            self._emit(event)
            return {"failed_auth_attempts": count, "pattern": "brute_force"}
        return {}

    def recent_anomalies(self, limit: int = 50) -> list[dict]:
        """Return the most recent anomaly events as dicts."""
        events = list(self._events)
        return [e.to_dict() for e in events[-limit:]]

    def stats(self) -> dict:
        return {
            "tracked_keys": len(self._connections),
            "tracked_ips_ports": len(self._ports),
            "total_events": len(self._events),
        }

    # ── Internal ────────────────────────────────────────────────────────────

    def _emit(self, event: AnomalyEvent) -> None:
        self._events.append(event)
        log.warning(
            "anomaly_detected",
            type=event.anomaly_type,
            severity=event.severity,
            entity=event.entity_id,
            details=event.details,
        )
