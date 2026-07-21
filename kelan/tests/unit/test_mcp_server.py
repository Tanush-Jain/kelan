"""Unit tests for standalone MCP server and companion SKILL.md."""

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

# Resolve the MCP server module from its canonical location so that both
# pytest (run from any cwd) and Pyrefly's static analyser can find it.
import importlib.util as _ilu

_SERVER_PY = Path(__file__).resolve().parents[3] / "kelan-agentbound-mcp" / "server.py"
_spec = _ilu.spec_from_file_location("agentbound_mcp_server", _SERVER_PY)
assert _spec is not None and _spec.loader is not None, f"Could not locate {_SERVER_PY}"
_server = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_server)  # type: ignore[union-attr]

handle_get_divergence_events = _server.handle_get_divergence_events
handle_get_session_summary   = _server.handle_get_session_summary
handle_start_monitoring      = _server.handle_start_monitoring
handle_stop_monitoring       = _server.handle_stop_monitoring
process_mcp_request          = _server.process_mcp_request



@pytest.mark.asyncio
async def test_mcp_server_jsonrpc_handshake_stdio():
    """
    CRITICAL SUCCESS CRITERION:
    server.py responds correctly to a manual MCP initialize + tools/list request over stdio.
    """
    # Test initialize request
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    }
    init_resp = await process_mcp_request(init_req)
    assert init_resp is not None
    assert init_resp["id"] == 1
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"
    assert init_resp["result"]["serverInfo"]["name"] == "kelan-agentbound"

    # Test tools/list request
    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    list_resp = await process_mcp_request(list_req)
    assert list_resp is not None
    assert list_resp["id"] == 2
    tools = list_resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]

    assert "start_monitoring" in tool_names
    assert "get_divergence_events" in tool_names
    assert "get_session_summary" in tool_names
    assert "stop_monitoring" in tool_names


def test_mcp_server_raw_subprocess_stdio_handshake():
    """
    MANUAL STDIO HANDSHAKE TEST:
    Spawns server.py as a child process, pipes JSON-RPC over stdin/stdout, and verifies response.
    """
    server_py = Path(__file__).resolve().parents[3] / "kelan-agentbound-mcp" / "server.py"
    cmd = [sys.executable, str(server_py)]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    init_msg = json.dumps({"jsonrpc": "2.0", "id": 100, "method": "initialize", "params": {}}) + "\n"
    list_msg = json.dumps({"jsonrpc": "2.0", "id": 101, "method": "tools/list", "params": {}}) + "\n"

    stdout_data, _ = proc.communicate(input=init_msg + list_msg, timeout=5)

    lines = [line.strip() for line in stdout_data.splitlines() if line.strip()]
    assert len(lines) >= 2

    resp1 = json.loads(lines[0])
    resp2 = json.loads(lines[1])

    assert resp1["id"] == 100
    assert resp1["result"]["serverInfo"]["name"] == "kelan-agentbound"

    assert resp2["id"] == 101
    tools = resp2["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "start_monitoring" in tool_names
    assert "get_divergence_events" in tool_names


def test_skill_md_yaml_schema_valid():
    """
    CRITICAL SUCCESS CRITERION:
    SKILL.md validates against schema (YAML frontmatter parses, required fields present).
    """
    skill_path = Path(__file__).resolve().parents[3] / "kelan-agentbound-skill" / "SKILL.md"
    assert skill_path.exists()

    content = skill_path.read_text(encoding="utf-8")
    assert content.startswith("---")
    parts = content.split("---", 2)
    assert len(parts) >= 3

    yaml_text = parts[1]
    import yaml
    data = yaml.safe_load(yaml_text)

    assert "name" in data
    assert data["name"] == "agentbound-monitoring"
    assert "description" in data
    assert "tags" in data
    assert "security" in data["tags"]
    assert "ebpf" in data["tags"]


@pytest.mark.asyncio
async def test_end_to_end_mcp_monitoring_divergence():
    """
    CRITICAL SUCCESS CRITERION:
    One end-to-end test: start_monitoring on a process, get_divergence_events returns
    classified divergence analysis.
    """
    my_pid = os.getpid()

    # 1. Start monitoring
    start_res = handle_start_monitoring(my_pid)
    assert start_res["status"] == "active"
    session_id = start_res["session_id"]
    assert session_id.startswith("session_")

    # 2. Get divergence events
    div_res = await handle_get_divergence_events(session_id)
    assert div_res["session_id"] == session_id
    assert div_res["pid"] == my_pid
    assert "divergence_detected" in div_res
    assert "verdict" in div_res
    assert "confidence" in div_res

    # 3. Get session summary
    sum_res = handle_get_session_summary(session_id)
    assert sum_res["session_id"] == session_id
    assert "summary" in sum_res

    # 4. Stop monitoring
    stop_res = handle_stop_monitoring(session_id)
    assert stop_res["status"] == "stopped"
