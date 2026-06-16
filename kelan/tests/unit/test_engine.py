"""Tests for HybridTrustEngine — mocks Ollama."""
import asyncio
import pytest
from unittest.mock import AsyncMock
from kelan.ai.engine import HybridTrustEngine, CircuitBreaker, CBState, _fallback
from kelan.ai.ollama_client import TrustVerdict, Verdict, OllamaClient


class TestCircuitBreaker:

    def test_starts_closed(self):
        cb = CircuitBreaker(threshold=3)
        assert cb.state == CBState.CLOSED
        assert cb.allow

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(threshold=3)
        cb.failure(); cb.failure(); cb.failure()
        assert cb.state == CBState.OPEN
        assert not cb.allow

    def test_closes_on_success(self):
        cb = CircuitBreaker(threshold=3)
        cb.failure(); cb.failure(); cb.failure()
        cb.success()
        assert cb.state == CBState.CLOSED

    def test_half_open_after_recovery(self):
        import time
        cb = CircuitBreaker(threshold=1, recovery=0)
        cb.failure()
        assert cb.state == CBState.OPEN
        time.sleep(0.01)
        assert cb.allow  # triggers half-open
        assert cb.state == CBState.HALF_OPEN


class TestFallbackRules:

    def test_syn_flood_deny(self):
        v = _fallback({"anomalies": {"syn_rate_per_second": 200}})
        assert v.verdict == Verdict.DENY

    def test_port_scan_deny(self):
        v = _fallback({"anomalies": {"ports_probed": 1000}})
        assert v.verdict == Verdict.DENY

    def test_sybil_deny(self):
        v = _fallback({"anomalies": {"enrollment_count_from_ip": 50}})
        assert v.verdict == Verdict.DENY

    def test_clean_allow(self):
        v = _fallback({"anomalies": {}})
        assert v.verdict == Verdict.ALLOW

    def test_anomalies_monitor(self):
        v = _fallback({"anomalies": {"unusual_timing": True}})
        assert v.verdict == Verdict.MONITOR


class TestHybridEngine:

    @pytest.mark.asyncio
    async def test_ollama_verdict_propagated(self):
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.evaluate.return_value = TrustVerdict(
            Verdict.DENY, 0.95, "test deny"
        )
        engine = HybridTrustEngine(mock_ollama)
        v = await engine.evaluate({"entity_id": "test", "anomalies": {}})
        assert v.verdict    == Verdict.DENY
        assert v.confidence == 0.95

    @pytest.mark.asyncio
    async def test_fallback_on_ollama_error(self):
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.evaluate.side_effect = ConnectionError("Ollama down")
        engine = HybridTrustEngine(mock_ollama, threshold=1)
        v = await engine.evaluate({"entity_id": "test", "anomalies": {}})
        # Should use fallback — not crash
        assert v.verdict in (Verdict.ALLOW, Verdict.MONITOR, Verdict.DENY)

    @pytest.mark.asyncio
    async def test_circuit_open_uses_fallback(self):
        mock_ollama = AsyncMock(spec=OllamaClient)
        engine = HybridTrustEngine(mock_ollama, threshold=1)
        engine.cb.failure()  # Force open
        v = await engine.evaluate({"entity_id": "test",
                                   "anomalies": {"syn_rate_per_second": 500}})
        assert v.verdict == Verdict.DENY
        mock_ollama.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_verdict_hook_called(self):
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.evaluate.return_value = TrustVerdict(Verdict.ALLOW, 0.9, "ok")
        engine = HybridTrustEngine(mock_ollama)
        received = []
        engine.on_verdict(lambda p: received.append(p) or asyncio.sleep(0))

        async def hook(payload):
            received.append(payload)

        engine.on_verdict(hook)
        await engine.evaluate({"entity_id": "e1", "anomalies": {}})
        assert len(received) >= 1
        assert received[-1]["verdict"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_slow_successful_verdict_does_not_open_circuit(self):
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.evaluate.return_value = TrustVerdict(
            Verdict.DENY, 0.95, "slow response but ok", latency_ms=65000.0
        )
        engine = HybridTrustEngine(mock_ollama, threshold=3)
        
        # Call evaluate
        v = await engine.evaluate({"entity_id": "test", "anomalies": {}})
        
        # Verify circuit is CLOSED, success was called, and verdict is returned (not fallback)
        assert engine.cb.state == CBState.CLOSED
        assert v.verdict == Verdict.DENY
        assert v.reason == "slow response but ok"

