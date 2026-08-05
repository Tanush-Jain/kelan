"""
HybridTrustEngine — Ollama + circuit breaker + fallback rules.
Replaces Rust HybridTrustEngine completely.
"""
import time
from enum import Enum
from typing import Awaitable, Callable, cast
import structlog
from .ollama_client import OllamaClient, TrustVerdict, Verdict
from prometheus_client import Counter, Histogram, Gauge, REGISTRY

if "kelan_verdicts_total" in REGISTRY._names_to_collectors:
    VERDICTS = cast(Counter, REGISTRY._names_to_collectors["kelan_verdicts_total"])
else:
    VERDICTS = Counter(
      "kelan_verdicts_total",
      "Trust verdicts by type",
      ["verdict","model","via_ollama"]
    )

if "kelan_ollama_latency_seconds" in REGISTRY._names_to_collectors:
    OLLAMA_LATENCY = cast(Histogram, REGISTRY._names_to_collectors["kelan_ollama_latency_seconds"])
else:
    OLLAMA_LATENCY = Histogram(
      "kelan_ollama_latency_seconds",
      "Ollama inference time",
      buckets=[.1,.25,.5,1,2.5,5,10]
    )

if "kelan_circuit_breaker_open" in REGISTRY._names_to_collectors:
    CIRCUIT_STATE = cast(Gauge, REGISTRY._names_to_collectors["kelan_circuit_breaker_open"])
else:
    CIRCUIT_STATE = Gauge(
      "kelan_circuit_breaker_open",
      "Circuit breaker state (1=open)"
    )

log = structlog.get_logger()
VerdictHook = Callable[[dict], Awaitable[None]]


class CBState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, threshold: int = 3, recovery: int = 30):
        self.threshold = threshold
        self.recovery  = recovery
        self.failures  = 0
        self.opened_at = 0.0
        self.state     = CBState.CLOSED

    def success(self):
        was_open = self.state != CBState.CLOSED
        self.failures = 0
        self.state    = CBState.CLOSED
        if was_open:
            log.info("circuit_closed")

    def failure(self):
        self.failures  += 1
        self.opened_at  = time.time()
        if self.failures >= self.threshold:
            self.state = CBState.OPEN
            log.warning("circuit_opened", failures=self.failures)

    @property
    def allow(self) -> bool:
        if self.state == CBState.CLOSED:
            return True
        if self.state == CBState.OPEN:
            if time.time() - self.opened_at > self.recovery:
                self.state = CBState.HALF_OPEN
                log.info("circuit_half_open")
                return True
            return False
        return True   # HALF_OPEN: probe


def _fallback(session: dict) -> TrustVerdict:
    """Deterministic rules — runs when Ollama is unavailable."""
    a = session.get("anomalies", {}) or {}
    if not isinstance(a, dict):
        return TrustVerdict(Verdict.MONITOR, 0.5, "fallback:non_dict_anomalies")

    checks = [
        (a.get("syn_rate_per_second", 0) > 100,  Verdict.DENY, "fallback:syn_flood"),
        (a.get("ports_probed", 0)        > 500,  Verdict.DENY, "fallback:port_scan"),
        (a.get("enrollment_count_from_ip",0) > 20, Verdict.DENY, "fallback:sybil"),
        (a.get("failed_auth_attempts", 0) > 50,  Verdict.DENY, "fallback:brute_force"),
        (bool(a),                                 Verdict.MONITOR, "fallback:anomalies_present"),
    ]
    for condition, verdict, reason in checks:
        if condition:
            return TrustVerdict(verdict, 0.85, reason)

    return TrustVerdict(Verdict.ALLOW, 0.75, "fallback:clean_session")


class HybridTrustEngine:

    def __init__(
        self,
        ollama:    OllamaClient,
        threshold: int = 3,
        recovery:  int = 30,
    ):
        self.ollama = ollama
        self.cb     = CircuitBreaker(threshold, recovery)
        self._hooks: list[VerdictHook] = []
        self._counts = dict(total=0, allow=0, deny=0, monitor=0, fallbacks=0)

    def on_verdict(self, fn: VerdictHook):
        self._hooks.append(fn)

    @property
    def stats(self) -> dict:
        return {**self._counts, "circuit": self.cb.state.value,
                "cache": self.ollama.cache_stats}

    async def evaluate(self, session: dict) -> TrustVerdict:
        via_ollama = False
        if not self.cb.allow:
            verdict = _fallback(session)
            self._counts["fallbacks"] += 1
        else:
            try:
                t0 = time.monotonic()
                verdict = await self.ollama.evaluate(session)
                via_ollama = True
                if verdict.reason.startswith("ollama_error:"):
                    self.cb.failure()
                    verdict = _fallback(session)
                    self._counts["fallbacks"] += 1
                else:
                    self.cb.success()
                OLLAMA_LATENCY.observe(time.monotonic() - t0)
            except Exception as exc:
                self.cb.failure()
                verdict = _fallback(session)
                self._counts["fallbacks"] += 1
                log.error("engine_fallback", error=str(exc))

        k = verdict.verdict.value.lower()
        self._counts["total"]  += 1
        if self._counts.get(k) is not None:
            self._counts.update({k: self._counts[k] + 1})

        # Record prometheus metrics
        VERDICTS.labels(
            verdict=verdict.verdict.value,
            model=getattr(self.ollama, "model", "qwen2.5:3b"),
            via_ollama="true" if via_ollama else "false"
        ).inc()
        CIRCUIT_STATE.set(1 if self.cb.state == CBState.OPEN else 0)

        payload = {**session, **verdict.to_dict(),
                   "action": "REVOKE" if verdict.verdict == Verdict.DENY else "PERMIT"}
        for hook in self._hooks:
            try:
                await hook(payload)
            except Exception as exc:
                log.error("hook_error", error=str(exc))

        return verdict
