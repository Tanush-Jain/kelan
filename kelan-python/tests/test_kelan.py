"""
Kelan Security Python — test suite
Covers FIX 1 (session leak) and all core modules.
Run: .venv/bin/python -m pytest -x --tb=short -q
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── helpers ────────────────────────────────────────────────────────────────────

def _make_session(entity_id="ent-001", intent="INIT_ENROL",
                  source_ip="10.0.0.1", anomalies=None):
    return {
        "entity_id": entity_id,
        "intent": intent,
        "session_id": "sess-test-1",
        "source_ip": source_ip,
        "anomalies": anomalies or {},
        "has_kem_key": False,
        "has_signature": False,
        "timestamp": "2026-01-01T00:00:00Z",
    }


def _mock_httpx_client():
    """Return a fully mocked httpx.AsyncClient that never touches the network."""
    client = MagicMock()
    client.is_closed = False
    client.aclose = AsyncMock()
    return client


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — FIX 1: OllamaClient shared session (no per-request creation)
# ══════════════════════════════════════════════════════════════════════════════

class TestOllamaClientSessionLeak:
    """
    FIX 1 — Verify that OllamaClient creates ONE shared httpx.AsyncClient
    and reuses it across calls, never creating a new one per request.
    All tests use mocked httpx clients — no network calls made.
    """

    def test_client_starts_as_none(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient(endpoint="http://localhost:11434", model="qwen2.5:3b")
        assert c._client is None, "Client must not be created at __init__"

    def test_session_lock_is_created(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient(endpoint="http://localhost:11434", model="qwen2.5:3b")
        assert hasattr(c, "_session_lock"), "_session_lock must exist (FIX 1)"
        assert isinstance(c._session_lock, asyncio.Lock)

    async def test_get_client_returns_shared_instance(self):
        """_get_client() must return the same object on every call — no new clients."""
        from kelan.ai.ollama_client import OllamaClient

        c = OllamaClient(endpoint="http://localhost:11434", model="qwen2.5:3b")
        mock = _mock_httpx_client()

        with patch("httpx.AsyncClient", return_value=mock):
            client_a = await c._get_client()
            client_b = await c._get_client()
            client_c = await c._get_client()

        assert client_a is client_b, "Must reuse same client (FIX 1)"
        assert client_b is client_c, "Must reuse same client (FIX 1)"
        # httpx.AsyncClient constructor called exactly once
        assert mock is client_a

    async def test_concurrent_get_client_returns_same_instance(self):
        """Under concurrent load, still only ONE client is created."""
        from kelan.ai.ollama_client import OllamaClient

        c = OllamaClient(endpoint="http://localhost:11434", model="qwen2.5:3b")
        mock = _mock_httpx_client()

        with patch("httpx.AsyncClient", return_value=mock):
            results = await asyncio.gather(*[c._get_client() for _ in range(20)])

        unique_clients = set(id(r) for r in results)
        assert len(unique_clients) == 1, (
            f"FIX 1 FAILED: {len(unique_clients)} clients created under load "
            f"(expected 1)"
        )

    async def test_close_cleans_up_client(self):
        from kelan.ai.ollama_client import OllamaClient

        c = OllamaClient(endpoint="http://localhost:11434", model="qwen2.5:3b")
        mock = _mock_httpx_client()

        with patch("httpx.AsyncClient", return_value=mock):
            await c._get_client()   # create it
            assert c._client is not None
            await c.close()

        mock.aclose.assert_called_once()

    async def test_get_client_recreates_when_closed(self):
        """After the client is closed, the next _get_client() makes a fresh one."""
        from kelan.ai.ollama_client import OllamaClient

        c = OllamaClient(endpoint="http://localhost:11434", model="qwen2.5:3b")
        mock1 = _mock_httpx_client()
        mock2 = _mock_httpx_client()

        with patch("httpx.AsyncClient", side_effect=[mock1, mock2]):
            client_1 = await c._get_client()
            # simulate external close
            c._client = mock1
            mock1.is_closed = True
            client_2 = await c._get_client()

        assert client_1 is mock1
        assert client_2 is mock2
        assert client_1 is not client_2, "Must create new client after close"

    def test_no_aiohttp_in_ollama_client(self):
        """aiohttp was the leaking library in the Rust migration. Must not appear."""
        import kelan.ai.ollama_client as mod
        import inspect
        src = inspect.getsource(mod)
        assert "aiohttp" not in src, (
            "aiohttp found in ollama_client.py — this would cause memory leaks!"
        )

    def test_no_per_request_client_creation_in_generate(self):
        """_generate() must not create a new httpx.AsyncClient inline."""
        import kelan.ai.ollama_client as mod
        import inspect
        src = inspect.getsource(mod.OllamaClient._generate)
        assert "httpx.AsyncClient(" not in src, (
            "httpx.AsyncClient() found inside _generate() — this leaks clients "
            "on every trust evaluation call!"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Model configuration
# ══════════════════════════════════════════════════════════════════════════════

class TestModelConfiguration:
    def test_qwen_options_temperature(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        opts = c._get_model_options()
        assert opts["temperature"] == 0.1

    def test_qwen_options_num_predict(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        opts = c._get_model_options()
        assert opts["num_predict"] == 80

    def test_qwen_options_stop_tokens(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        opts = c._get_model_options()
        assert "<|im_end|>" in opts["stop"], "qwen2.5 must use chat-template stop token"

    def test_unknown_model_has_fallback_options(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "unknownmodel:99b")
        opts = c._get_model_options()
        assert "temperature" in opts
        assert "num_predict" in opts

    def test_model_from_env_when_arg_empty(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "")
        assert c.model == "qwen2.5:3b"

    def test_model_arg_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "gemma3:9b")
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        assert c.model == "qwen2.5:3b", "Explicit arg must override env var"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Prompt builder
# ══════════════════════════════════════════════════════════════════════════════

class TestPromptBuilder:
    def test_qwen_prompt_uses_im_start_token(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
        from kelan.ai import prompts
        prompt = prompts.build_evaluation_prompt(_make_session())
        assert "<|im_start|>" in prompt

    def test_qwen_prompt_uses_im_end_token(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
        from kelan.ai import prompts
        prompt = prompts.build_evaluation_prompt(_make_session())
        assert "<|im_end|>" in prompt

    def test_generic_prompt_has_deny_rules(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "llama3:8b")
        from kelan.ai import prompts
        prompt = prompts.build_evaluation_prompt(_make_session())
        assert "DENY" in prompt

    def test_prompt_contains_entity_id(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
        from kelan.ai import prompts
        session = _make_session(entity_id="my-unique-entity-xyz")
        prompt = prompts.build_evaluation_prompt(session)
        assert "my-unique-entity-xyz" in prompt

    def test_verify_prompt_has_status_ok(self):
        from kelan.ai.prompts import VERIFY_PROMPT
        assert "status" in VERIFY_PROMPT
        assert "ok" in VERIFY_PROMPT


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Verdict parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestVerdictParsing:
    def test_parse_clean_allow_json(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict('{"verdict":"ALLOW","confidence":0.9,"reason":"ok"}')
        assert v.verdict.value == "ALLOW"
        assert v.confidence == 0.9

    def test_parse_deny_verdict(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict('{"verdict":"DENY","confidence":0.95,"reason":"flood"}')
        assert v.verdict.value == "DENY"

    def test_parse_monitor_verdict(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict('{"verdict":"MONITOR","confidence":0.6,"reason":"new entity"}')
        assert v.verdict.value == "MONITOR"

    def test_parse_embedded_json_in_freetext(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        raw = 'Some text before {"verdict":"MONITOR","confidence":0.6,"reason":"new"} after'
        v = c._parse_verdict(raw)
        assert v.verdict.value == "MONITOR"

    def test_low_confidence_overrides_to_monitor(self):
        from kelan.ai.ollama_client import OllamaClient, Verdict
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict('{"verdict":"DENY","confidence":0.3,"reason":"weak"}')
        assert v.verdict == Verdict.MONITOR, "confidence<0.5 must override verdict to MONITOR"

    def test_keyword_fallback_deny(self):
        from kelan.ai.ollama_client import OllamaClient, Verdict
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict("DENY this request immediately")
        assert v.verdict == Verdict.DENY

    def test_keyword_fallback_allow(self):
        from kelan.ai.ollama_client import OllamaClient, Verdict
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict("This looks ALLOW-able")
        assert v.verdict == Verdict.ALLOW

    def test_unparseable_returns_monitor(self):
        from kelan.ai.ollama_client import OllamaClient, Verdict
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        v = c._parse_verdict("totally garbled output xyz 123")
        assert v.verdict == Verdict.MONITOR

    def test_reason_truncated_to_100_chars(self):
        from kelan.ai.ollama_client import OllamaClient
        c = OllamaClient("http://localhost:11434", "qwen2.5:3b")
        long_reason = "x" * 200
        v = c._parse_verdict(
            json.dumps({"verdict": "ALLOW", "confidence": 0.9, "reason": long_reason})
        )
        assert len(v.reason) <= 100


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Circuit breaker
# ══════════════════════════════════════════════════════════════════════════════

class TestCircuitBreaker:
    def test_starts_closed(self):
        from kelan.ai.engine import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        assert cb.state == CircuitState.CLOSED

    def test_allows_request_when_closed(self):
        from kelan.ai.engine import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        assert cb.allows_request is True

    def test_opens_after_threshold_failures(self):
        from kelan.ai.engine import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_blocks_request_when_open(self):
        from kelan.ai.engine import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        for _ in range(3):
            cb.record_failure()
        assert cb.allows_request is False

    def test_closes_after_success(self):
        from kelan.ai.engine import CircuitBreaker, CircuitState
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        for _ in range(3):
            cb.record_failure()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_success_resets_failure_count(self):
        from kelan.ai.engine import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.failure_count == 0

    def test_to_dict_structure(self):
        from kelan.ai.engine import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        d = cb.to_dict()
        assert d["state"] == "closed"
        assert d["failures"] == 0
        assert d["threshold"] == 5


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Fallback rule engine
# ══════════════════════════════════════════════════════════════════════════════

class TestFallbackRules:
    def test_clean_session_allows(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session())
        assert v.verdict == Verdict.ALLOW

    def test_syn_flood_denies(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session(anomalies={"syn_rate_per_second": 200}))
        assert v.verdict == Verdict.DENY

    def test_port_scan_denies(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session(anomalies={"ports_probed": 600}))
        assert v.verdict == Verdict.DENY

    def test_sybil_burst_denies(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session(anomalies={"enrollment_count_from_ip": 25}))
        assert v.verdict == Verdict.DENY

    def test_brute_force_denies(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session(anomalies={"failed_auth_attempts": 60}))
        assert v.verdict == Verdict.DENY

    def test_udp_flood_denies(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session(anomalies={"udp_rate_per_second": 600}))
        assert v.verdict == Verdict.DENY

    def test_minor_anomaly_monitors(self):
        from kelan.ai.engine import fallback_rules
        from kelan.ai.ollama_client import Verdict
        v = fallback_rules(_make_session(anomalies={"unusual_timing": True}))
        assert v.verdict == Verdict.MONITOR

    def test_fallback_verdict_has_reason(self):
        from kelan.ai.engine import fallback_rules
        v = fallback_rules(_make_session())
        assert v.reason.startswith("fallback:")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — HybridTrustEngine (all Ollama calls mocked)
# ══════════════════════════════════════════════════════════════════════════════

class TestHybridTrustEngine:
    async def test_uses_fallback_when_circuit_open(self):
        from kelan.ai.engine import HybridTrustEngine, CircuitState
        mock_ollama = MagicMock()
        mock_ollama.evaluate_session = AsyncMock()
        engine = HybridTrustEngine(ollama=mock_ollama, failure_threshold=3, recovery_timeout=30)
        for _ in range(3):
            engine.circuit.record_failure()
        assert engine.circuit.state == CircuitState.OPEN

        await engine.evaluate(_make_session())
        mock_ollama.evaluate_session.assert_not_called()
        assert engine._fallback_calls == 1

    async def test_records_success_on_ollama_ok(self):
        from kelan.ai.engine import HybridTrustEngine
        from kelan.ai.ollama_client import TrustVerdict, Verdict
        expected = TrustVerdict(Verdict.ALLOW, 0.9, "ok")
        mock_ollama = MagicMock()
        mock_ollama.evaluate_session = AsyncMock(return_value=expected)
        engine = HybridTrustEngine(ollama=mock_ollama)

        verdict = await engine.evaluate(_make_session())

        assert verdict.verdict == Verdict.ALLOW
        assert engine._ollama_calls == 1
        assert engine._fallback_calls == 0
        assert engine.circuit.failure_count == 0

    async def test_falls_back_on_ollama_exception(self):
        from kelan.ai.engine import HybridTrustEngine
        mock_ollama = MagicMock()
        mock_ollama.evaluate_session = AsyncMock(side_effect=RuntimeError("timeout"))
        engine = HybridTrustEngine(ollama=mock_ollama)

        await engine.evaluate(_make_session())

        assert engine._fallback_calls == 1
        assert engine.circuit.failure_count == 1

    async def test_broadcasts_verdict_to_callback(self):
        from kelan.ai.engine import HybridTrustEngine
        from kelan.ai.ollama_client import TrustVerdict, Verdict
        expected = TrustVerdict(Verdict.ALLOW, 0.9, "broadcast-test")
        mock_ollama = MagicMock()
        mock_ollama.evaluate_session = AsyncMock(return_value=expected)
        engine = HybridTrustEngine(ollama=mock_ollama)

        received: list[dict] = []
        async def capture(payload: dict):
            received.append(payload)

        engine.on_verdict(capture)
        await engine.evaluate(_make_session())

        assert len(received) == 1
        assert received[0]["verdict"] == "ALLOW"
        assert "entity_id" in received[0]
        assert "session_id" in received[0]

    async def test_total_evaluations_count(self):
        from kelan.ai.engine import HybridTrustEngine
        from kelan.ai.ollama_client import TrustVerdict, Verdict
        mock_ollama = MagicMock()
        mock_ollama.evaluate_session = AsyncMock(
            return_value=TrustVerdict(Verdict.ALLOW, 0.9, "ok")
        )
        engine = HybridTrustEngine(ollama=mock_ollama)
        for _ in range(5):
            await engine.evaluate(_make_session())
        assert engine._total_evaluations == 5

    def test_stats_has_required_keys(self):
        from kelan.ai.engine import HybridTrustEngine
        engine = HybridTrustEngine(ollama=MagicMock())
        s = engine.stats()
        assert "total_evaluations" in s
        assert "ollama_calls" in s
        assert "fallback_calls" in s
        assert "circuit_breaker" in s


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — Sentinel anomaly engine (memory bounds)
# ══════════════════════════════════════════════════════════════════════════════

class TestSentinelEngine:
    def test_clean_session_returns_empty_dict(self):
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        result = s.analyze("ent-001", "DATA_TRANSFER", "1.2.3.4")
        assert result == {}

    def test_sybil_burst_detected(self):
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        result = {}
        for i in range(s.ENROLL_BURST_LIMIT + 2):
            result = s.analyze(f"ent-{i}", "INIT_ENROL", "10.0.0.1")
        assert result.get("rapid_enrollment_burst") is True

    def test_connection_flood_detected(self):
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        result = {}
        for _ in range(s.CONN_FLOOD_LIMIT + 5):
            result = s.analyze("ent-flood", "DATA", "10.0.0.2")
        assert "syn_rate_per_second" in result

    def test_events_deque_is_bounded_at_1000(self):
        """Memory safety: deque(maxlen=1000) — never grows unbounded."""
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        for i in range(2000):
            s.analyze(f"ent-{i % 5}", "INIT_ENROL", f"10.0.{i % 256}.1")
        assert len(s._events) <= 1000

    def test_brute_force_flag_above_limit(self):
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        result = {}
        for _ in range(s.BRUTE_FORCE_LIMIT + 1):
            result = s.record_failed_auth("ent-brute")
        assert result.get("failed_auth_attempts", 0) > s.BRUTE_FORCE_LIMIT

    def test_recent_anomalies_returns_list(self):
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        anomalies = s.recent_anomalies(limit=10)
        assert isinstance(anomalies, list)

    def test_stats_has_required_keys(self):
        from kelan.sentinel.anomaly import SentinelEngine
        s = SentinelEngine()
        st = s.stats()
        assert "tracked_keys" in st
        assert "total_events" in st


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — Session manager (memory bounds + eviction)
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionManager:
    def _allow(self):
        from kelan.ai.ollama_client import TrustVerdict, Verdict
        return TrustVerdict(Verdict.ALLOW, 0.9, "ok")

    def _deny(self):
        from kelan.ai.ollama_client import TrustVerdict, Verdict
        return TrustVerdict(Verdict.DENY, 0.95, "flood")

    def test_store_and_retrieve(self):
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=100)
        rec = sm.store("sess-1", "ent-1", self._allow())
        assert rec.session_id == "sess-1"
        assert rec.entity_id == "ent-1"

    def test_allow_gets_permit_token(self):
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=100)
        rec = sm.store("sess-allow", "ent-1", self._allow())
        assert rec.permit_token is not None

    def test_deny_has_no_permit_token(self):
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=100)
        rec = sm.store("sess-deny", "ent-bad", self._deny())
        assert rec.permit_token is None

    def test_capacity_evicts_oldest(self):
        """Sessions beyond capacity are evicted — no unbounded memory growth."""
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=10)
        for i in range(20):
            sm.store(f"sess-{i}", "ent", self._allow())
        assert len(sm._sessions) <= 10

    def test_recent_verdicts_respects_limit(self):
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=5000)
        for i in range(100):
            sm.store(f"sess-{i}", "ent", self._allow())
        verdicts = sm.recent_verdicts(limit=10)
        assert len(verdicts) == 10

    def test_count_by_verdict(self):
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=100)
        sm.store("s1", "e1", self._allow())
        sm.store("s2", "e2", self._deny())
        counts = sm.count_by_verdict()
        assert counts["ALLOW"] == 1
        assert counts["DENY"] == 1

    def test_stats_structure(self):
        from kelan.protocol.session import SessionManager
        sm = SessionManager(capacity=100)
        sm.store("s1", "e1", self._allow())
        st = sm.stats()
        assert st["total_sessions"] == 1
        assert "by_verdict" in st
        assert "capacity" in st


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — Settings / config
# ══════════════════════════════════════════════════════════════════════════════

class TestSettings:
    def test_ollama_model_from_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
        from kelan.config import get_settings
        get_settings.cache_clear()
        s = get_settings()
        assert s.ollama_model == "qwen2.5:3b"
        get_settings.cache_clear()

    def test_ollama_endpoint_contains_port(self):
        from kelan.config import get_settings
        get_settings.cache_clear()
        s = get_settings()
        assert "11434" in s.ollama_endpoint
        get_settings.cache_clear()

    def test_circuit_breaker_threshold_positive(self):
        from kelan.config import get_settings
        get_settings.cache_clear()
        s = get_settings()
        assert s.cb_failure_threshold > 0
        get_settings.cache_clear()

    def test_circuit_breaker_timeout_positive(self):
        from kelan.config import get_settings
        get_settings.cache_clear()
        s = get_settings()
        assert s.cb_recovery_timeout > 0
        get_settings.cache_clear()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — eBPF bridge (graceful no-op when loader absent)
# ══════════════════════════════════════════════════════════════════════════════

class TestEbpfBridge:
    async def test_block_ip_returns_false_when_no_socket(self):
        from kelan.enforcement.ebpf_bridge import EbpfBridge
        bridge = EbpfBridge(socket_path="/nonexistent/kelan-ebpf.sock")
        result = await bridge.block_ip("1.2.3.4", reason="test", duration_secs=60)
        assert result is False

    async def test_unblock_ip_returns_false_when_no_socket(self):
        from kelan.enforcement.ebpf_bridge import EbpfBridge
        bridge = EbpfBridge(socket_path="/nonexistent/kelan-ebpf.sock")
        result = await bridge.unblock_ip("1.2.3.4")
        assert result is False

    async def test_is_available_false_when_no_socket(self):
        from kelan.enforcement.ebpf_bridge import EbpfBridge
        bridge = EbpfBridge(socket_path="/nonexistent/kelan-ebpf.sock")
        assert await bridge.is_available() is False

    async def test_report_drop_count_returns_none(self):
        from kelan.enforcement.ebpf_bridge import EbpfBridge
        bridge = EbpfBridge(socket_path="/nonexistent/kelan-ebpf.sock")
        result = await bridge.report_drop_count()
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — FIX 2: Database session leak (get_db context manager)
# ══════════════════════════════════════════════════════════════════════════════

class TestDatabaseSessionLeak:
    """
    FIX 2 — get_db() always commits on success, rolls back on exception,
    and closes the session in `finally` — connections never orphaned.
    Uses in-memory SQLite; no external services needed.
    """

    async def test_get_db_raises_when_not_initialised(self):
        """get_db() must raise RuntimeError if init_db() was never called."""
        import kelan.database as db_mod
        original = db_mod._session_factory
        db_mod._session_factory = None
        try:
            with pytest.raises(RuntimeError, match="not initialised"):
                async with db_mod.get_db() as _:
                    pass
        finally:
            db_mod._session_factory = original

    async def test_init_and_close_db(self, tmp_path, monkeypatch):
        """init_db() creates engine+factory; close_db() disposes cleanly."""
        import kelan.database as db_mod
        monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/t.db")
        db_mod._engine = None
        db_mod._session_factory = None
        try:
            await db_mod.init_db()
            assert db_mod._engine is not None
            assert db_mod._session_factory is not None
        finally:
            await db_mod.close_db()
            db_mod._engine = None
            db_mod._session_factory = None

    async def test_get_db_commits_on_success(self, tmp_path, monkeypatch):
        """commit() called once on clean exit; rollback() never called."""
        import kelan.database as db_mod
        monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/t.db")
        db_mod._engine = None
        db_mod._session_factory = None
        committed, rolled_back = [], []
        try:
            await db_mod.init_db()
            real_factory = db_mod._session_factory
            assert real_factory is not None

            # async_sessionmaker.__call__() is synchronous — spy must be a plain def
            def spy_factory():
                s = real_factory()
                orig_c, orig_r = s.commit, s.rollback
                async def tc(): committed.append(1); return await orig_c()
                async def tr(): rolled_back.append(1); return await orig_r()
                s.commit, s.rollback = tc, tr  # type: ignore
                return s

            db_mod._session_factory = spy_factory  # type: ignore
            async with db_mod.get_db() as _:
                pass
            assert committed == [1],   "commit() must be called exactly once"
            assert rolled_back == [],  "rollback() must NOT be called on success"
        finally:
            await db_mod.close_db()
            db_mod._engine = None
            db_mod._session_factory = None

    async def test_get_db_rolls_back_on_exception(self, tmp_path, monkeypatch):
        """rollback() + close() always called on exception — never leaks."""
        import kelan.database as db_mod
        monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/t.db")
        db_mod._engine = None
        db_mod._session_factory = None
        rolled_back, closed = [], []
        try:
            await db_mod.init_db()
            real_factory = db_mod._session_factory
            assert real_factory is not None

            # async_sessionmaker.__call__() is synchronous — spy must be a plain def
            def spy_factory():
                s = real_factory()
                orig_r, orig_cl = s.rollback, s.close
                async def tr(): rolled_back.append(1); return await orig_r()
                async def tcl(): closed.append(1); return await orig_cl()
                s.rollback, s.close = tr, tcl  # type: ignore
                return s

            db_mod._session_factory = spy_factory  # type: ignore
            with pytest.raises(ValueError):
                async with db_mod.get_db() as _:
                    raise ValueError("simulated failure")
            assert rolled_back == [1], "rollback() must be called on exception"
            assert closed == [1],      "close() must always be called (finally)"
        finally:
            await db_mod.close_db()
            db_mod._engine = None
            db_mod._session_factory = None

    def test_no_direct_session_factory_calls_in_server(self):
        """
        VERIFY (FIX 2): server/main.py must not call _session_factory() directly.
        All DB access must go through `async with get_db() as db:`.
        """
        import inspect
        import kelan.server.main as main_mod
        src = inspect.getsource(main_mod)
        assert "_session_factory()" not in src, (
            "Found _session_factory() in server/main.py — use get_db() instead"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — FIX 3: Stats endpoint (2-second cache + TypeError guards)
# ══════════════════════════════════════════════════════════════════════════════

class TestStatsEndpoint:
    """FIX 3 — _compute_stats() never crashes; get_verdicts() returns a dict."""

    def _swap(self, main_mod, sessions=None, engine=None, sentinel=None):
        """Context helper — swap globals, yield, restore."""
        orig = (main_mod.sessions, main_mod.engine, main_mod.sentinel)
        main_mod.sessions = sessions
        main_mod.engine   = engine
        main_mod.sentinel = sentinel
        return orig

    def test_compute_stats_has_required_keys(self):
        import kelan.server.main as m
        orig = self._swap(m)
        try:
            result = m._compute_stats()
            for k in ("mode", "uptime_seconds", "verdicts", "engine",
                      "sentinel", "circuit_state", "ollama_model"):
                assert k in result, f"Missing key: {k}"
        finally:
            m.sessions, m.engine, m.sentinel = orig

    def test_compute_stats_survives_all_none(self):
        """_compute_stats() must not raise when all singletons are None."""
        import kelan.server.main as m
        orig = self._swap(m)
        try:
            result = m._compute_stats()
            assert isinstance(result, dict)
            assert result["verdicts"] == {}
        finally:
            m.sessions, m.engine, m.sentinel = orig

    def test_circuit_state_is_always_a_string(self):
        import kelan.server.main as m
        orig = self._swap(m)
        try:
            assert isinstance(m._compute_stats()["circuit_state"], str)
        finally:
            m.sessions, m.engine, m.sentinel = orig

    def test_stats_cache_module_vars_exist(self):
        import kelan.server.main as m
        assert hasattr(m, "_stats_cache"), "_stats_cache must exist (FIX 3)"
        assert hasattr(m, "STATS_TTL"),    "STATS_TTL must exist (FIX 3)"
        assert m.STATS_TTL > 0

    async def test_get_verdicts_returns_dict_with_total(self):
        import kelan.server.main as m
        import kelan.protocol.session as sm_mod
        from kelan.ai.ollama_client import TrustVerdict, Verdict
        sm = sm_mod.SessionManager(capacity=100)
        for i in range(5):
            sm.store(f"s{i}", "ent", TrustVerdict(Verdict.ALLOW, 0.9, "ok"))
        orig_sessions = m.sessions
        m.sessions = sm
        try:
            result = await m.get_verdicts(limit=10)
            assert "verdicts" in result, "Must have 'verdicts' key"
            assert "total"    in result, "Must have 'total' key (FIX 3)"
            assert isinstance(result["verdicts"], list)
        finally:
            m.sessions = orig_sessions

    async def test_get_verdicts_no_sessions_returns_total_zero(self):
        import kelan.server.main as m
        orig_sessions = m.sessions
        m.sessions = None
        try:
            result = await m.get_verdicts()
            assert result == {"verdicts": [], "total": 0}
        finally:
            m.sessions = orig_sessions

    def test_no_plain_list_module_globals_in_server(self):
        """VERIFY (FIX 3): no bare `= []` at module level in server/main.py."""
        import inspect
        import kelan.server.main as m
        src = inspect.getsource(m)
        bad = [
            line.strip() for line in src.splitlines()
            if line.strip().endswith("= []")
            and not line.strip().startswith("#")
            and not line.strip().startswith("return")
        ]
        assert bad == [], f"Bare list assignments found at module level: {bad}"
