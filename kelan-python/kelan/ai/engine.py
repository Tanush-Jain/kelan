"""
HybridTrustEngine — main AI trust evaluation with circuit breaker.
Replaces the Rust HybridTrustEngine (aitp-ai-engine) entirely.

Architecture:
  1. Check circuit breaker state
  2. If CLOSED → try Ollama (gemma4:latest)
  3. If OPEN / error → fall back to deterministic rule engine
  4. Broadcast verdict to all connected WebSocket agents
"""
import time
from enum import Enum
from typing import Callable, Awaitable
import structlog

from .ollama_client import OllamaClient, TrustVerdict, Verdict

log = structlog.get_logger()


class CircuitState(Enum):
    CLOSED = "closed"       # Normal — Ollama is healthy
    OPEN = "open"           # Ollama failed repeatedly — using fallback
    HALF_OPEN = "half_open" # Testing if Ollama has recovered


class CircuitBreaker:
    """
    Standard circuit-breaker pattern protecting Ollama calls.
    CLOSED → OPEN after `failure_threshold` consecutive failures.
    OPEN → HALF_OPEN after `recovery_timeout` seconds.
    HALF_OPEN → CLOSED on first success, OPEN on failure.
    """

    def __init__(self, failure_threshold: int = 3, recovery_timeout: int = 30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0

    def record_success(self) -> None:
        if self.state != CircuitState.CLOSED:
            log.info("circuit_breaker_closed", previous=self.state.value)
        self.failure_count = 0
        self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        if self.failure_count >= self.failure_threshold:
            if self.state != CircuitState.OPEN:
                log.warning(
                    "circuit_breaker_opened",
                    failures=self.failure_count,
                    threshold=self.failure_threshold,
                )
            self.state = CircuitState.OPEN

    @property
    def allows_request(self) -> bool:
        """True when a request should be forwarded to Ollama."""
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.monotonic() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                log.info("circuit_breaker_half_open")
                return True
            return False
        # HALF_OPEN — allow one probe
        return True

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "failures": self.failure_count,
            "threshold": self.failure_threshold,
        }


# ── Deterministic fallback rule engine ────────────────────────────────────────

def fallback_rules(session: dict) -> TrustVerdict:
    """
    Deterministic rule engine used when Ollama is unavailable.
    Conservative — anything anomalous → MONITOR to avoid false positives.
    Hard rate violations → DENY immediately.
    """
    anomalies = session.get("anomalies", {})

    # Hard DENY rules
    if anomalies.get("syn_rate_per_second", 0) > 100:
        return TrustVerdict(Verdict.DENY, 0.95, "fallback:syn_flood_rate>100/s")

    if anomalies.get("ports_probed", 0) > 500:
        return TrustVerdict(Verdict.DENY, 0.90, "fallback:port_scan>500_ports")

    if anomalies.get("enrollment_count_from_ip", 0) > 20:
        return TrustVerdict(Verdict.DENY, 0.90, "fallback:sybil_burst>20_enrollments")

    if anomalies.get("failed_auth_attempts", 0) > 50:
        return TrustVerdict(Verdict.DENY, 0.85, "fallback:brute_force>50_attempts")

    if anomalies.get("udp_rate_per_second", 0) > 500:
        return TrustVerdict(Verdict.DENY, 0.90, "fallback:udp_flood_rate>500/s")

    # Soft anomalies → MONITOR
    if anomalies:
        return TrustVerdict(Verdict.MONITOR, 0.60, "fallback:anomalies_present_ollama_unavailable")

    # Clean session → ALLOW
    return TrustVerdict(Verdict.ALLOW, 0.75, "fallback:clean_session_ollama_unavailable")


# ── Main Engine ────────────────────────────────────────────────────────────────

VerdictCallback = Callable[[dict], Awaitable[None]]


class HybridTrustEngine:
    """
    Primary trust evaluation engine:
      - Tries Ollama first (circuit-breaker protected)
      - Falls back to deterministic rules when Ollama is down
      - Broadcasts every verdict to registered WebSocket callbacks
    """

    def __init__(
        self,
        ollama: OllamaClient,
        failure_threshold: int = 3,
        recovery_timeout: int = 30,
    ):
        self.ollama = ollama
        self.circuit = CircuitBreaker(failure_threshold, recovery_timeout)
        self._callbacks: list[VerdictCallback] = []
        self._total_evaluations = 0
        self._ollama_calls = 0
        self._fallback_calls = 0

    def on_verdict(self, callback: VerdictCallback) -> None:
        """Register an async callback that receives every verdict payload."""
        self._callbacks.append(callback)

    async def evaluate(self, session: dict) -> TrustVerdict:
        """
        Evaluate a session and return a verdict.
        Always broadcasts the verdict before returning.
        """
        self._total_evaluations += 1
        entity_id = session.get("entity_id", "unknown")

        if not self.circuit.allows_request:
            log.warning("circuit_open_using_fallback", entity=entity_id)
            self._fallback_calls += 1
            verdict = fallback_rules(session)
            await self._broadcast(session, verdict, source="fallback:circuit_open")
            return verdict

        try:
            verdict = await self.ollama.evaluate_session(session)
            self.circuit.record_success()
            self._ollama_calls += 1
            await self._broadcast(session, verdict, source="ollama")
            return verdict

        except Exception as exc:
            self.circuit.record_failure()
            self._fallback_calls += 1
            log.error("ollama_failed_using_fallback", error=str(exc), entity=entity_id)
            verdict = fallback_rules(session)
            await self._broadcast(session, verdict, source="fallback:ollama_error")
            return verdict

    async def _broadcast(self, session: dict, verdict: TrustVerdict, source: str) -> None:
        """Notify all registered WebSocket clients of the new verdict."""
        payload = {
            "type": "verdict",
            "entity_id": session.get("entity_id", "unknown"),
            "session_id": session.get("session_id", ""),
            "verdict": verdict.verdict.value,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "action": "REVOKE" if verdict.verdict == Verdict.DENY else "PERMIT",
            "source": source,
        }
        dead: list[VerdictCallback] = []
        for cb in self._callbacks:
            try:
                await cb(payload)
            except Exception as exc:
                log.error("broadcast_callback_error", error=str(exc))
                dead.append(cb)
        for cb in dead:
            self._callbacks.remove(cb)

    def stats(self) -> dict:
        return {
            "total_evaluations": self._total_evaluations,
            "ollama_calls": self._ollama_calls,
            "fallback_calls": self._fallback_calls,
            "circuit_breaker": self.circuit.to_dict(),
        }
