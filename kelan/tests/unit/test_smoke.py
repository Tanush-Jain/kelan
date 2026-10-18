"""Smoke and unit tests for EbpfBridge and FallbackRulesEngine."""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from kelan.trust.fallback_rules import FallbackRulesEngine
from kelan.enforcement.ebpf_bridge import EbpfBridge, LOADER_BINARY

@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"

@pytest.mark.asyncio
async def test_fallback_rules_engine():
    engine = FallbackRulesEngine()
    # Test synthetic flood payload trigger (syn_rate_per_second > 100)
    ctx = {
        "entity_id": "test-entity",
        "intent": "TEST",
        "anomalies": {"syn_rate_per_second": 150}
    }
    res = await engine.evaluate(ctx)
    assert res["verdict"] == "DENY"
    assert "syn_flood" in res["reason"]
    assert res["confidence"] == 0.85

    # Test clean allow trigger
    ctx_clean = {
        "entity_id": "test-entity",
        "intent": "TEST",
        "anomalies": {}
    }
    res_clean = await engine.evaluate(ctx_clean)
    assert res_clean["verdict"] == "ALLOW"
    assert res_clean["confidence"] == 0.75

@pytest.mark.asyncio
async def test_ebpf_bridge_software_mode():
    # Force LOADER_BINARY to not exist so it starts in software fallback mode
    with patch("pathlib.Path.exists", return_value=False):
        bridge = EbpfBridge(iface="eth99")
        await bridge.start()
        assert bridge.mode == "software"
        
        # Test permit, revoke, stats do not crash and log/do nothing
        await bridge.permit("sess-1", "entity-1", "1.1.1.1")
        await bridge.revoke("entity-1")
        stats = await bridge.drop_stats()
        assert stats == {}
        
        await bridge.stop()

@pytest.mark.asyncio
async def test_ebpf_bridge_ebpf_mode_success():
    # Force LOADER_BINARY to exist and mock create_subprocess_exec
    with patch("pathlib.Path.exists", return_value=True):
        mock_proc = MagicMock()
        mock_proc.pid = 9876
        mock_proc.stdin = MagicMock()
        mock_proc.stdin.drain = AsyncMock()
        mock_proc.wait = AsyncMock()
        
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_proc
            
            bridge = EbpfBridge(iface="eth0")
            await bridge.start()
            assert bridge.mode == "ebpf"
            mock_exec.assert_called_once_with(
                str(LOADER_BINARY),
                "--interface", "eth0",
                "--ipc-mode", "stdin",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Test permit
            await bridge.permit("sess-1", "entity-1", "1.1.1.1")
            expected_permit = json.dumps({
                "action": "PERMIT", "session_id": "sess-1",
                "entity_id": "entity-1", "src_ip": "1.1.1.1"
            }).encode() + b"\n"
            mock_proc.stdin.write.assert_called_with(expected_permit)
            
            # Test revoke
            await bridge.revoke("entity-2")
            expected_revoke = json.dumps({
                "action": "REVOKE", "entity_id": "entity-2"
            }).encode() + b"\n"
            mock_proc.stdin.write.assert_called_with(expected_revoke)
            
            await bridge.stop()
            mock_proc.terminate.assert_called_once()
            mock_proc.wait.assert_called_once()

@pytest.mark.asyncio
async def test_ebpf_bridge_drop_stats_mock():
    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(return_value=(b"bpftool raw output", b""))
    
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_proc
        
        bridge = EbpfBridge(iface="eth0")
        bridge._mode = "ebpf"
        stats = await bridge.drop_stats()
        
        mock_exec.assert_called_once_with(
            "bpftool", "map", "dump", "name", "SYN_RATE",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        assert stats == {"raw": "bpftool raw output"}
