"""Integration tests for FastAPI endpoints — mocks Ollama."""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from httpx import AsyncClient, ASGITransport

from kelan.ai.ollama_client import TrustVerdict, Verdict, OllamaClient
from kelan.ai.engine import HybridTrustEngine
from kelan.protocol.handshake import HandshakeManager
from kelan.db.database import init_db

@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def client():
    """Create test client with mocked Ollama."""
    import kelan.api.server as s

    # Ensure DB is initialized for integration endpoints
    await init_db()

    mock_ollama = AsyncMock(spec=OllamaClient)
    mock_ollama.ping.return_value = True
    mock_ollama.list_models.return_value = ["gemma4:latest"]
    mock_ollama.evaluate.return_value = TrustVerdict(Verdict.ALLOW, 0.90, "test allow")
    mock_ollama.cache_stats = {"hits": 0, "misses": 0, "size": 0}

    s.ollama  = mock_ollama
    s.engine  = HybridTrustEngine(mock_ollama)
    s.engine.on_verdict(s._on_verdict)

    from kelan.sentinel.detector import SentinelDetector
    from kelan.enforcement.ebpf_bridge import EbpfBridge
    s.sentinel     = SentinelDetector()
    s.ebpf         = AsyncMock(spec=EbpfBridge)
    s.ebpf.mode    = "software"
    s.handshake_mgr = HandshakeManager(require_pq=False)

    # Disable require_pq by default so legit tests succeed without kem keys
    old_pq = s.cfg.require_pq
    s.cfg.require_pq = False

    transport = ASGITransport(app=s.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    s.cfg.require_pq = old_pq


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "healthy"
    assert "version" in d
    assert "ollama_model" in d


@pytest.mark.asyncio
async def test_stats(client):
    r = await client.get("/api/stats")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_enroll_legit(client):
    r = await client.post("/api/enroll", json={
        "entity_id": "test-server-001",
        "intent":    "INIT_ENROL",
        "name":      "TestServer",
    })
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"]     == "ALLOW"
    assert d["confidence"]  >= 0.5
    assert "session_id"     in d
    assert "permit_token"   in d


@pytest.mark.asyncio
async def test_enroll_spoofed_sig_rejected(client):
    r = await client.post("/api/enroll", json={
        "entity_id": "evil-entity",
        "intent":    "INIT_ENROL",
        "signature": "00" * 64,
    })
    assert r.status_code == 403
    assert "signature" in r.json()["detail"]["error"]


@pytest.mark.asyncio
async def test_pq_required(client):
    import kelan.api.server as s
    old_pq = s.cfg.require_pq
    s.cfg.require_pq = True
    s.handshake_mgr = HandshakeManager(require_pq=True)
    try:
        r = await client.post("/api/enroll", json={
            "entity_id": "no-kem-entity",
            "intent":    "INIT_ENROL",
        })
        assert r.status_code == 403
    finally:
        s.cfg.require_pq = old_pq


@pytest.mark.asyncio
async def test_verdicts_endpoint(client):
    r = await client.get("/api/verdicts")
    assert r.status_code == 200
    assert "verdicts" in r.json()


@pytest.mark.asyncio
async def test_anomalies_endpoint(client):
    r = await client.get("/api/anomalies")
    assert r.status_code == 200
    assert isinstance(r.json()["anomalies"], list)


@pytest.mark.asyncio
async def test_sentinel_events(client):
    r = await client.get("/api/sentinel/events")
    assert r.status_code == 200
    assert "events" in r.json()


@pytest.mark.asyncio
async def test_xdp_drop_endpoint(client):
    r = await client.post("/api/xdp/drop", json={"count": 100, "interface": "eth0"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_handshake_pq_downgrade_rejected(client):
    import kelan.api.server as s
    old_pq = s.cfg.require_pq
    s.cfg.require_pq = True
    s.handshake_mgr = HandshakeManager(require_pq=True)
    try:
        r = await client.post("/api/handshake", json={
            "entity_id": "downgrade-test",
            "phase":     1,
            "intent":    "INIT_SESSION",
        })
        # With require_pq and no kem_public_key in phase 1, should fail with 403
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "pq_downgrade_denied"
    finally:
        s.cfg.require_pq = old_pq


@pytest.mark.asyncio
async def test_enroll_pq_downgrade_rejected(client):
    import kelan.api.server as s
    old_pq = s.cfg.require_pq
    s.cfg.require_pq = True
    try:
        r = await client.post("/api/enroll", json={
            "entity_id": "downgrade-enroll-test",
            "intent":    "INIT_ENROL",
        })
        assert r.status_code == 403
        data = r.json()
        assert data["detail"]["error"] == "pq_downgrade_denied"
        assert "Post-quantum key exchange required" in data["detail"]["reason"]
    finally:
        s.cfg.require_pq = old_pq

