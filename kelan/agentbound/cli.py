"""
AgentBound CLI — Monitor-Only Agent Security CLI (`kelan bound`).

Monitor-only MVP:
1. Scans /proc for candidate agent processes.
2. Attaches retargeted sentinel probes.
3. Periodically extracts declared intent and correlates observed kernel events.
4. Renders a live terminal table.
5. Appends classified audit events to a JSON-lines audit file.

NOTE: STRICTLY MONITOR-ONLY. Zero blocking, zero LSM, zero enforcement logic.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional
import structlog

from kelan.sentinel.detector import SentinelDetector
from .intent_extractor import AgentIntent, extract_intent, read_proc_environ
from .behavior_engine import BehaviorEngine, BehaviorVerdict

log = structlog.get_logger()


def scan_agent_processes() -> list[int]:
    """Scan /proc for candidate agent process PIDs based on binary names or env signatures."""
    my_pid = os.getpid()
    candidate_pids: list[int] = []

    proc_dir = Path("/proc")
    if not proc_dir.exists():
        return candidate_pids

    known_binaries = ("claude", "claude-code", "cursor", "copilot", "aider", "ollama", "open-interpreter")
    known_env_prefixes = ("CLAUDE_", "CURSOR_", "ANTHROPIC_", "OPENAI_")

    for entry in proc_dir.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            if pid == my_pid:
                continue

            cmdline_file = entry / "cmdline"
            if cmdline_file.exists():
                cmd = cmdline_file.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").lower()
                if any(b in cmd for b in known_binaries):
                    candidate_pids.append(pid)
                    continue

            # Check environment signatures
            env = read_proc_environ(pid)
            if any(any(k.startswith(p) for p in known_env_prefixes) for k in env):
                candidate_pids.append(pid)
        except (PermissionError, FileNotFoundError, ProcessLookupError, ValueError):
            continue

    return candidate_pids


def _render_terminal_table(rows: list[dict]) -> None:
    """Print ASCII table of monitored agent processes to stdout."""
    header = f"{'PID':<8} | {'AGENT TYPE':<15} | {'LAST ACTION':<30} | {'IN-SCOPE?':<10} | {'REASON':<45}"
    divider = "-" * len(header)
    
    print("\n" + divider)
    print(header)
    print(divider)

    if not rows:
        print("No active agent processes detected in /proc.")
        print(divider + "\n")
        return

    for r in rows:
        pid_str = str(r.get("pid", ""))[:8]
        atype = str(r.get("agent_type", ""))[:15]
        action = str(r.get("action", ""))[:30]
        in_scope = "YES" if r.get("in_scope") else "NO (FLAGGED)"
        reason = str(r.get("reason", ""))[:45]

        print(f"{pid_str:<8} | {atype:<15} | {action:<30} | {in_scope:<10} | {reason:<45}")

    print(divider + "\n")


def append_json_line(log_path: Path | str, event_data: dict) -> None:
    """Append a single audit event record to JSON-lines audit file."""
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data) + "\n")


async def run_agentbound_monitor(
    interval: float = 2.0,
    log_path: Path | str = "agentbound_audit.jsonl",
    once: bool = False,
    target_pid: Optional[int] = None,
) -> list[dict]:
    """
    Main monitor loop for kelan bound.
    
    Monitor-only execution: scans PIDs, extracts intent, correlates events, prints live table,
    and appends JSON-lines audit log.
    """
    detector = SentinelDetector()
    engine = BehaviorEngine()
    processed_records: list[dict] = []

    while True:
        pids = [target_pid] if target_pid else scan_agent_processes()
        table_rows: list[dict] = []

        for pid in pids:
            intent = extract_intent(pid)
            events = detector.recent(20)

            # Evaluate correlation
            verdict: BehaviorVerdict = await engine.evaluate(intent, events)

            last_action = "file_access:none"
            if events:
                e = events[-1]
                last_action = f"{e.get('kind', 'event')}:{e.get('details', {}).get('path', 'kernel_event')}"

            in_scope = not verdict.divergence_detected
            record = {
                "timestamp": round(time.time(), 3),
                "pid": pid,
                "agent_type": intent.agent_type,
                "action": last_action,
                "in_scope": in_scope,
                "reason": verdict.reason,
                "confidence": round(verdict.confidence, 3),
            }

            table_rows.append(record)
            processed_records.append(record)
            append_json_line(log_path, record)

        _render_terminal_table(table_rows)

        if once:
            break

        await asyncio.sleep(interval)

    return processed_records


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point for kelan bound."""
    parser = argparse.ArgumentParser(
        prog="kelan bound",
        description="Kelan AgentBound — Monitor-Only Agent Security CLI",
    )
    parser.add_argument("--interval", "-i", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--log-file", "-l", type=str, default="agentbound_audit.jsonl", help="Output JSON-lines log path")
    parser.add_argument("--once", action="store_true", help="Run one iteration and exit")
    parser.add_argument("--pid", "-p", type=int, default=None, help="Target specific agent PID")

    args = parser.parse_args(argv)

    print(f"Starting Kelan AgentBound Monitor (log: {args.log_file})...")
    try:
        asyncio.run(run_agentbound_monitor(
            interval=args.interval,
            log_path=args.log_file,
            once=args.once,
            target_pid=args.pid,
        ))
    except KeyboardInterrupt:
        print("\nAgentBound Monitor stopped.")


if __name__ == "__main__":
    main()
