"""
Kelan AgentBound MCP Server — Standalone stdio MCP Transport.

Exposes AgentBound monitor-only tools via Model Context Protocol over stdio for any
MCP-capable host (Claude Code, Gemini CLI, Antigravity, Grok Build, Codex, ChatGPT Apps).
"""

from __future__ import annotations
import asyncio
import json
import os
import sys
import time
import uuid
from typing import Any, Optional
import structlog

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kelan.agentbound import (
    AgentIntent,
    BehaviorEngine,
    BehaviorVerdict,
    extract_intent,
    get_daily_summary_payload,
    scan_agent_processes,
)
from kelan.sentinel.detector import SentinelDetector

log = structlog.get_logger()

ACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}
ENGINE = BehaviorEngine()
DETECTOR = SentinelDetector()


def handle_start_monitoring(agent_pid_or_name: Any) -> dict[str, Any]:
    """Attach probes and start a monitoring session for an agent PID or process name."""
    target_pid: Optional[int] = None

    if isinstance(agent_pid_or_name, int) or (isinstance(agent_pid_or_name, str) and agent_pid_or_name.isdigit()):
        target_pid = int(agent_pid_or_name)
    else:
        pids = scan_agent_processes()
        if pids:
            target_pid = pids[0]

    if target_pid is None:
        target_pid = os.getpid()

    intent: AgentIntent = extract_intent(target_pid)
    session_id = f"session_{target_pid}_{uuid.uuid4().hex[:8]}"

    ACTIVE_SESSIONS[session_id] = {
        "session_id": session_id,
        "pid": target_pid,
        "intent": intent,
        "agent_type": intent.agent_type,
        "started_at": round(time.time(), 3),
        "last_check": round(time.time(), 3),
    }

    return {
        "status": "active",
        "session_id": session_id,
        "pid": target_pid,
        "agent_type": intent.agent_type,
        "declared_paths": intent.declared_paths,
        "declared_task": intent.declared_task,
    }


async def handle_get_divergence_events(session_id: str) -> dict[str, Any]:
    """Return classified events and behavioral divergence analysis since last call."""
    sess = ACTIVE_SESSIONS.get(session_id)
    if not sess:
        return {"error": f"Session ID {session_id} not found or inactive."}

    intent: AgentIntent = sess["intent"]
    events = DETECTOR.recent(20)

    verdict: BehaviorVerdict = await ENGINE.evaluate(intent, events)
    sess["last_check"] = round(time.time(), 3)

    return {
        "session_id": session_id,
        "pid": sess["pid"],
        "agent_type": sess["agent_type"],
        "divergence_detected": verdict.divergence_detected,
        "verdict": verdict.verdict.value if hasattr(verdict.verdict, "value") else str(verdict.verdict),
        "reason": verdict.reason,
        "confidence": round(verdict.confidence, 3),
        "recent_events_count": len(events),
        "events": events[-5:],
    }


def handle_get_session_summary(session_id: str) -> dict[str, Any]:
    """Return aggregate statistics for the session (uses behavior_index.py's daily rollup)."""
    sess = ACTIVE_SESSIONS.get(session_id)
    if not sess:
        return {"error": f"Session ID {session_id} not found or inactive."}

    payload = get_daily_summary_payload()
    agent_summary = payload.get("summary", {}).get(sess["agent_type"], {
        "total_events": 0,
        "in_scope_events": 0,
        "out_of_scope_events": 0,
    })

    return {
        "session_id": session_id,
        "agent_type": sess["agent_type"],
        "summary": agent_summary,
    }


def handle_stop_monitoring(session_id: str) -> dict[str, Any]:
    """Stop monitoring session and detach probes."""
    sess = ACTIVE_SESSIONS.pop(session_id, None)
    if not sess:
        return {"error": f"Session ID {session_id} not found or already stopped."}

    return {
        "status": "stopped",
        "session_id": session_id,
        "pid": sess["pid"],
        "agent_type": sess["agent_type"],
    }


TOOLS_MANIFEST = [
    {
        "name": "start_monitoring",
        "description": "Attach eBPF behavior probes and start a monitoring session for an agent PID or binary name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_pid_or_name": {
                    "type": "string",
                    "description": "Target agent process PID or binary name (e.g. 1234, 'claude', 'cursor')",
                }
            },
            "required": ["agent_pid_or_name"],
        },
    },
    {
        "name": "get_divergence_events",
        "description": "Return classified kernel events and behavioral divergence evaluation for a monitoring session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active monitoring session ID returned by start_monitoring",
                }
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "get_session_summary",
        "description": "Return aggregate telemetry statistics for a monitoring session (daily aggregate counters).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active monitoring session ID",
                }
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "stop_monitoring",
        "description": "Stop monitoring session and detach sentinel probes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active monitoring session ID",
                }
            },
            "required": ["session_id"],
        },
    },
]


async def process_mcp_request(request: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Process a single JSON-RPC 2.0 MCP request."""
    method = request.get("method")
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kelan-agentbound", "version": "1.0.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS_MANIFEST},
        }

    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        res_data: Any = None
        if tool_name == "start_monitoring":
            res_data = handle_start_monitoring(args.get("agent_pid_or_name", ""))
        elif tool_name == "get_divergence_events":
            res_data = await handle_get_divergence_events(str(args.get("session_id", "")))
        elif tool_name == "get_session_summary":
            res_data = handle_get_session_summary(str(args.get("session_id", "")))
        elif tool_name == "stop_monitoring":
            res_data = handle_stop_monitoring(str(args.get("session_id", "")))
        else:
            res_data = {"error": f"Unknown tool: {tool_name}"}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(res_data, indent=2),
                    }
                ]
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method {method} not found"},
    }


async def run_mcp_stdio_server() -> None:
    """Run MCP stdio transport loop."""
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            break

        line_str = line.decode("utf-8").strip()
        if not line_str:
            continue

        try:
            req = json.loads(line_str)
            resp = await process_mcp_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as err:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": f"Internal error: {err}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


def main() -> None:
    """Entry point for standalone MCP stdio server."""
    asyncio.run(run_mcp_stdio_server())


if __name__ == "__main__":
    main()
