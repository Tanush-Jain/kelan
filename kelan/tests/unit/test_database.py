
import os

import pytest
import pytest_asyncio

from kelan.config import get_settings
from kelan.db.database import (
    fetch_anomalies,
    fetch_verdicts,
    init_db,
    save_anomaly,
    save_verdict,
)


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"

@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():

    old_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    get_settings.cache_clear()
    

    await init_db()
    
    yield
    

    if old_db_url:
        os.environ["DATABASE_URL"] = old_db_url
    else:
        os.environ.pop("DATABASE_URL", None)
    get_settings.cache_clear()

@pytest.mark.asyncio
async def test_save_and_fetch_verdict():

    session_id = "test-session-123"
    entity_id = "test-entity-456"
    verdict = "ALLOW"
    confidence = 0.95
    reason = "No anomalies detected"
    latency_ms = 45.2
    anomalies = {"port_scan": False, "syn_flood": False}
    
    await save_verdict(
        session_id=session_id,
        entity_id=entity_id,
        verdict=verdict,
        confidence=confidence,
        reason=reason,
        latency_ms=latency_ms,
        anomalies=anomalies
    )
    

    verdicts = await fetch_verdicts(limit=10)
    assert len(verdicts) >= 1
    

    saved = verdicts[0]
    assert saved["session_id"] == session_id
    assert saved["entity_id"] == entity_id
    assert saved["verdict"] == verdict
    assert saved["confidence"] == confidence
    assert saved["reason"] == reason
    assert saved["latency_ms"] == latency_ms

@pytest.mark.asyncio
async def test_save_and_fetch_anomaly():

    source = "192.168.1.50"
    kind = "port_scan"
    severity = 0.85
    details = {"ports_scanned": [22, 80, 443], "rate": 15.4}
    
    await save_anomaly(
        source=source,
        kind=kind,
        severity=severity,
        details=details
    )
    

    anomalies = await fetch_anomalies(limit=10)
    assert len(anomalies) >= 1
    

    saved = anomalies[0]
    assert saved["source"] == source
    assert saved["kind"] == kind
    assert saved["severity"] == severity
    assert saved["details"] == details

def test_database_facade_wrapper():
    import kelan.database as db_facade
    assert db_facade.init_db is not None
