from __future__ import annotations
import asyncio
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
        return {
            "source": self.source, "kind": self.kind,
            "severity": self.severity, "details": self.details,
            "ts": round(self.ts, 2)
        }


def _sliding_count(q: deque, now: float, window: float) -> int:
    cutoff = now - window
    while q and q[0] <= cutoff:
        q.popleft()
    return len(q)


class SentinelDetector:

    def __init__(self) -> None:
        self._enroll:  dict[str, deque] = defaultdict(deque)
        self._connect: dict[str, deque] = defaultdict(deque)
        self._auth:    dict[str, deque] = defaultdict(deque)
        self._ports:   dict[str, set]   = defaultdict(set)
        self._events:  deque            = deque(maxlen=2000)

    def analyze(self, entity_id: str, intent: str, source_ip: str = "") -> dict[str, Any]:
        now = time.time()
        key = source_ip or entity_id
        out: dict = {}
        intent_up = intent.upper()

        # ── Enrollment burst (sybil) ──────────────────────────
        if "ENROL" in intent_up:
            q = self._enroll[key]
            q.append(now)
            count = _sliding_count(q, now, 5.0)
            if count > 10:
                out |= {
                    "rapid_enrollment_burst":    True,
                    "enrollment_count_from_ip":  count,
                    "enrollment_window_seconds": 5,
                    "pattern":                   "sybil_attack",
                }
                self._emit_and_save(AnomalyEvent(
                    key, "sybil_attack", 0.90,
                    {"count": count, "window": "5s"}
                ))

        # ── Connection rate (flood) ───────────────────────────
        q2 = self._connect[key]
        q2.append(now)
        rate = _sliding_count(q2, now, 1.0)
        if rate > 50:
            out |= {
                "syn_rate_per_second": rate,
                "threshold":           50,
                "pattern":             "flood_attack",
            }
            self._emit_and_save(AnomalyEvent(
                key, "flood", 0.95, {"rate": rate}
            ))

        # ── Auth failures (brute force) ───────────────────────
        if "AUTH" in intent_up:
            q3 = self._auth[key]
            q3.append(now)
            fails = _sliding_count(q3, now, 60.0)
            if fails > 20:
                out |= {
                    "failed_auth_attempts": fails,
                    "window_seconds":       60,
                    "pattern":              "brute_force",
                }
                self._emit_and_save(AnomalyEvent(
                    key, "brute_force", 0.85,
                    {"count": fails}
                ))

        return out

    def record_port_probe(self, source_ip: str, port: int) -> None:
        self._ports[source_ip].add(port)
        n = len(self._ports[source_ip])
        thresholds = {100: 0.6, 500: 0.75, 1000: 0.85, 5000: 0.95}
        if n in thresholds:
            self._emit_and_save(AnomalyEvent(
                source_ip, "port_scan", thresholds[n],
                {"ports_probed": n, "pattern": "reconnaissance"}
            ))
            log.warning("port_scan", src=source_ip, ports=n)

    # ── Agent Behavior Monitoring (AgentBound Phase 1) ────────

    def record_file_access(
        self,
        entity_id: str,
        path: str,
        declared_scope: list[str] | None = None,
        source_ip: str = ""
    ) -> dict[str, Any]:
        """Flag file access events (openat/open) outside declared scope or sensitive paths."""
        key = source_ip or entity_id
        sensitive_prefixes = ("/etc/ssh/", "/etc/shadow", "/etc/passwd", "/root/.ssh", "/root/.aws")
        out_of_scope = False
        reason = ""

        path_norm = path.replace("~", "/root")
        if any(path_norm.startswith(sp) or path.startswith(sp) for sp in sensitive_prefixes) or ".aws" in path or ".ssh" in path:
            out_of_scope = True
            reason = "restricted_sensitive_path"

        if not out_of_scope and declared_scope is not None:
            if not any(path.startswith(allowed) or path_norm.startswith(allowed) for allowed in declared_scope):
                out_of_scope = True
                reason = "file_path_outside_declared_scope"

        if out_of_scope:
            event = AnomalyEvent(
                key, "out_of_scope_file_access", 0.90,
                {"path": path, "reason": reason, "pattern": "unauthorized_file_access"}
            )
            self._emit_and_save(event)
            return {"out_of_scope_file_access": True, "path": path, "pattern": "unauthorized_file_access"}
        return {}

    def record_network_connect(
        self,
        entity_id: str,
        dest_host: str,
        port: int = 80,
        declared_scope: list[str] | None = None,
        source_ip: str = ""
    ) -> dict[str, Any]:
        """Relabel connect classification to evaluate target against agent declared network scope."""
        key = source_ip or entity_id
        target = f"{dest_host}:{port}"
        out_of_scope = False

        if declared_scope is not None:
            if dest_host not in declared_scope and target not in declared_scope:
                out_of_scope = True

        if out_of_scope:
            event = AnomalyEvent(
                key, "out_of_scope_network_connect", 0.85,
                {"dest_host": dest_host, "port": port, "pattern": "network_scope_violation"}
            )
            self._emit_and_save(event)
            return {"out_of_scope_network_connect": True, "target": target, "pattern": "network_scope_violation"}
        return {}

    def record_process_exec(
        self,
        entity_id: str,
        binary_path: str,
        args: list[str] | None = None,
        declared_scope: list[str] | None = None,
        source_ip: str = ""
    ) -> dict[str, Any]:
        """Flag process spawn events (execve) outside declared executable scope."""
        key = source_ip or entity_id
        out_of_scope = False
        args = args or []

        if declared_scope is not None:
            if binary_path not in declared_scope and not any(binary_path.endswith(b) for b in declared_scope):
                out_of_scope = True

        if out_of_scope:
            event = AnomalyEvent(
                key, "out_of_scope_process_spawn", 0.95,
                {"binary": binary_path, "args": args, "pattern": "unauthorized_execve"}
            )
            self._emit_and_save(event)
            return {"out_of_scope_process_spawn": True, "binary": binary_path, "pattern": "unauthorized_execve"}
        return {}

    def _emit_and_save(self, event: AnomalyEvent) -> None:
        self._events.append(event)
        log.warning("sentinel", kind=event.kind,
                    severity=event.severity, src=event.source)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                save_anomaly(event.source, event.kind,
                             event.severity, event.details)
            )
        except RuntimeError:
            pass

    def recent(self, n: int = 50) -> list[dict[str, Any]]:
        return [e.to_dict() for e in list(self._events)[-n:]]
