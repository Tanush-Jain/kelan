from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from kelan.api.server import app


@pytest.mark.asyncio
async def test_community_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["edition"] == "community"
        assert data["mode"] == "audit"


@pytest.mark.asyncio
async def test_community_stats_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["edition"] == "community"
        assert data["mode"] == "audit"
        assert data["active_enforcement"] is False


@pytest.mark.asyncio
async def test_community_verdicts_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/verdicts")
        assert resp.status_code == 200
        data = resp.json()
        assert "verdicts" in data
        assert "count" in data


@pytest.mark.asyncio
async def test_community_metrics_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert b"kelan_requests_total" in resp.content


@pytest.mark.asyncio
async def test_community_rejects_permit_revoke_endpoints():
    """Confirms that active enforcement endpoints (permit/revoke/xdp) are not mounted on Community server."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/xdp/drop", json={"src_ip": "10.0.0.1"})
        assert resp.status_code in (404, 405)

        resp2 = await client.post("/api/enroll", json={"entity_id": "test"})
        assert resp2.status_code in (404, 405)

