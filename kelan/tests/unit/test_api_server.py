"""Unit tests for FastAPI server endpoints and lifecycle."""
from typing import Any
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocketDisconnect
from httpx import AsyncClient, ASGITransport

from kelan.ai.ollama_client import TrustVerdict, Verdict
from kelan.protocol.handshake import HandshakeError
from kelan.api.server import (
    app, lifespan, _on_verdict, ws_agent, _ws_clients
)

@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"

class MockWebSocket:
    def __init__(self, received_messages=None):
        self.client = MagicMock()
        self.client.host = "127.0.0.1"
        self.client.port = 12345
        self.sent_messages = []
        self.received_messages = received_messages or [{"type": "ping"}]
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_json(self, data):
        self.sent_messages.append(data)

    async def receive_json(self):
        if not self.received_messages:
            raise WebSocketDisconnect()
        msg = self.received_messages.pop(0)
        if isinstance(msg, Exception):
            raise msg
        return msg

@pytest.mark.asyncio
async def test_server_lifespan():
    with patch("kelan.api.server.init_db", new_callable=AsyncMock) as mock_init_db, \
         patch("kelan.api.server.OllamaClient") as mock_ollama_class, \
         patch("kelan.api.server.EbpfBridge") as mock_ebpf_class:
         
         mock_ollama = mock_ollama_class.return_value
         mock_ollama.ping = AsyncMock(return_value=True)
         mock_ollama.list_models = AsyncMock(return_value=["model-1"])
         mock_ollama.close = AsyncMock()
         
         mock_ebpf = mock_ebpf_class.return_value
         mock_ebpf.start = AsyncMock()
         mock_ebpf.stop = AsyncMock()
         
         async with lifespan(app):
             pass
             
         mock_init_db.assert_called_once()
         mock_ollama.ping.assert_called_once()
         mock_ebpf.start.assert_called_once()
         mock_ebpf.stop.assert_called_once()
         mock_ollama.close.assert_called_once()

@pytest.mark.asyncio
async def test_on_verdict_broadcasting():
    import kelan.api.server as s
    s.ebpf = AsyncMock()
    
    mock_ws: Any = MockWebSocket([])
    _ws_clients.add(mock_ws)
    
    # Verdict payload with REVOKE
    payload_revoke = {
        "session_id": "sess-rev",
        "entity_id": "entity-rev",
        "verdict": "DENY",
        "confidence": 0.9,
        "action": "REVOKE",
        "reason": "malicious activity"
    }
    
    # Verdict payload with PERMIT
    payload_permit = {
        "session_id": "sess-perm",
        "entity_id": "entity-perm",
        "verdict": "ALLOW",
        "confidence": 0.8,
        "action": "PERMIT",
        "reason": "clean session"
    }
    
    # Call _on_verdict
    with patch("kelan.api.server.save_verdict", new_callable=AsyncMock) as mock_save:
        await _on_verdict(payload_revoke)
        s.ebpf.revoke.assert_called_once_with("entity-rev")
        
        await _on_verdict(payload_permit)
        s.ebpf.permit.assert_called_once_with("sess-perm", "entity-perm")
        
        mock_save.assert_called()
        
    assert len(mock_ws.sent_messages) == 2
    assert mock_ws.sent_messages[0]["session_id"] == "sess-rev"
    assert mock_ws.sent_messages[1]["session_id"] == "sess-perm"
    
    _ws_clients.discard(mock_ws)

@pytest.mark.asyncio
async def test_websocket_agent_disconnect():
    mock_ws: Any = MockWebSocket([{"type": "status"}, WebSocketDisconnect()])
    
    import kelan.api.server as s
    s.cfg = MagicMock()
    s.cfg.ollama_model = "test-model"
    s.cfg.require_pq = True
    
    await ws_agent(mock_ws)
    
    assert mock_ws.accepted is True
    assert len(mock_ws.sent_messages) == 2
    assert mock_ws.sent_messages[0]["type"] == "connected"
    assert mock_ws.sent_messages[1]["type"] == "ack"
    assert mock_ws not in _ws_clients

@pytest.mark.asyncio
async def test_websocket_agent_error():
    mock_ws: Any = MockWebSocket([Exception("WS Failure")])
    
    await ws_agent(mock_ws)
    assert mock_ws not in _ws_clients

@pytest.mark.asyncio
async def test_dashboard_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Mock FileResponse to avoid actual static file checking
        with patch("kelan.api.server.FileResponse") as mock_file_resp:
            mock_file_resp.return_value = MagicMock()
            
            r = await client.get("/")
            assert r.status_code == 200
            
            r_dash = await client.get("/dashboard")
            assert r_dash.status_code == 200

@pytest.mark.asyncio
async def test_trust_evaluate_endpoint():
    import kelan.api.server as s
    s.engine = AsyncMock()
    s.engine.evaluate.return_value = TrustVerdict(Verdict.ALLOW, 0.85, "clean trust")
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/trust/evaluate", json={
            "entity_id": "entity-123",
            "intent": "TEST",
            "session_id": "sess-123",
            "anomalies": [{"port_scan": True}] # List should be coerced to dict
        })
        assert r.status_code == 200
        d = r.json()
        assert d["verdict"] == "ALLOW"
        assert d["confidence"] == 0.85

@pytest.mark.asyncio
async def test_metrics_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/metrics")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]

@pytest.mark.asyncio
async def test_handshake_endpoint_errors():
    import kelan.api.server as s
    s.handshake_mgr = MagicMock()
    s.cfg = MagicMock()
    s.cfg.require_pq = True
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Phase 1, require_pq, missing kem_public_key -> 403
        r1 = await client.post("/api/handshake", json={
            "entity_id": "entity-1",
            "phase": 1,
        })
        assert r1.status_code == 403
        assert "pq_downgrade_denied" in r1.json()["detail"]["error"]
        
        # Phase 3, require_pq, missing kem_ciphertext -> 403
        r2 = await client.post("/api/handshake", json={
            "entity_id": "entity-1",
            "phase": 3,
        })
        assert r2.status_code == 403
        assert "pq_downgrade_denied" in r2.json()["detail"]["error"]
        
        # Phase 3, missing session_id -> 400
        s.cfg.require_pq = False
        r3 = await client.post("/api/handshake", json={
            "entity_id": "entity-1",
            "phase": 3,
            "kem_ciphertext": "ct",
            "signature": "sig",
            "ed25519_public_key": "pub"
        })
        assert r3.status_code == 400
        
        # Phase 3, HandshakeError -> 403
        s.handshake_mgr.receive_kem_complete.side_effect = HandshakeError("expired")
        r4 = await client.post("/api/handshake", json={
            "entity_id": "entity-1",
            "phase": 3,
            "session_id": "sess-1",
            "kem_ciphertext": "ct",
            "signature": "sig",
            "ed25519_public_key": "pub"
        })
        assert r4.status_code == 403
        
        # Unsupported phase -> 400
        r5 = await client.post("/api/handshake", json={
            "entity_id": "entity-1",
            "phase": 99,
        })
        assert r5.status_code == 400
