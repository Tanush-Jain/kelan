"""Unit tests for the Ollama client."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from kelan.ai.ollama_client import OllamaClient, Verdict

@pytest.mark.asyncio
async def test_ollama_ping_success():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        ok = await client.ping()
        assert ok is True
        mock_get.assert_called_once_with("/api/tags")
    await client.close()

@pytest.mark.asyncio
async def test_ollama_ping_failure():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("Connection refused")):
        ok = await client.ping()
        assert ok is False
    await client.close()

@pytest.mark.asyncio
async def test_ollama_list_models():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [
                {"name": "qwen2.5:3b"},
                {"name": "gemma4:latest"}
            ]
        }
        mock_get.return_value = mock_resp
        
        models = await client.list_models()
        assert models == ["qwen2.5:3b", "gemma4:latest"]
    await client.close()

@pytest.mark.asyncio
async def test_ollama_list_models_failure():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch("httpx.AsyncClient.get", side_effect=Exception("API Error")):
        models = await client.list_models()
        assert models == []
    await client.close()

@pytest.mark.asyncio
async def test_ollama_raw_generate_success():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "{\"verdict\": \"ALLOW\", \"confidence\": 0.9, \"reason\": \"clean\"}"}
        mock_post.return_value = mock_resp
        
        resp = await client._raw_generate("test prompt")
        assert "ALLOW" in resp
        mock_post.assert_called_once()
    await client.close()

@pytest.mark.asyncio
async def test_ollama_evaluate_success():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch.object(client, "_raw_generate", new_callable=AsyncMock) as mock_raw:
        mock_raw.return_value = "{\"verdict\": \"ALLOW\", \"confidence\": 0.9, \"reason\": \"clean\"}"
        
        session = {"entity_id": "test-1", "intent": "TEST", "anomalies": {}}
        verdict = await client.evaluate(session)
        assert verdict.verdict == Verdict.ALLOW
        assert verdict.confidence == 0.9
        assert verdict.from_cache is False
        assert client.cache_stats["misses"] == 1
        assert client.cache_stats["hits"] == 0
    await client.close()

@pytest.mark.asyncio
async def test_ollama_evaluate_cache_hits():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch.object(client, "_raw_generate", new_callable=AsyncMock) as mock_raw:
        # We need a DENY verdict with confidence >= 0.7 to cache it (per client.py line 203)
        mock_raw.return_value = "{\"verdict\": \"DENY\", \"confidence\": 0.8, \"reason\": \"malicious\"}"
        
        session = {"entity_id": "test-1", "intent": "TEST", "anomalies": {"syn_flood": True}}
        
        # Miss 1
        v1 = await client.evaluate(session)
        assert v1.verdict == Verdict.DENY
        assert v1.from_cache is False
        
        # Hit 1
        v2 = await client.evaluate(session)
        assert v2.verdict == Verdict.DENY
        assert v2.from_cache is True
        
        assert client.cache_stats["hits"] == 1
        assert client.cache_stats["misses"] == 1
    await client.close()

@pytest.mark.asyncio
async def test_ollama_evaluate_failure_fallback():
    client = OllamaClient("http://mock-ollama", "qwen2.5:3b")
    with patch.object(client, "_raw_generate", side_effect=Exception("Inference crashed")):
        session = {"entity_id": "test-1", "intent": "TEST", "anomalies": {}}
        verdict = await client.evaluate(session)
        assert verdict.verdict == Verdict.MONITOR
        assert verdict.confidence == 0.0
        assert "ollama_error" in verdict.reason
    await client.close()
