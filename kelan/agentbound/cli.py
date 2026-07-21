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


def _emit_claude_code_plugin_hint() -> None:
    """
    Emit a Claude Code plugin discovery hint to stderr.

    Only runs when invoked inside a Claude Code session (CLAUDECODE env var is
    set). The hint is stripped from tool output by Claude Code before the
    model sees it — zero token cost, zero noise for human users.

    Format: <claude-code-hint v="1" type="plugin" value="name@marketplace" />
    See Section 3 of the Claude Code Plugin spec.
    """
    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_CHILD_SESSION"):
        print(
            '<claude-code-hint v="1" type="plugin" value="kelan-agentbound@kelan-agentbound" />',
            file=sys.stderr,
            flush=True,
        )

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
    """Append a single audit event record with SHA-256 hash-chaining to JSON-lines audit file."""
    from .compliance_export import compute_entry_hash, GENESIS_HASH

    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = GENESIS_HASH
    if p.exists() and p.stat().st_size > 0:
        try:
            lines = p.read_text(encoding="utf-8").strip().splitlines()
            if lines:
                last_obj = json.loads(lines[-1])
                prev_hash = last_obj.get("entry_hash", GENESIS_HASH)
        except Exception:
            prev_hash = GENESIS_HASH

    event_data["prev_hash"] = prev_hash
    event_data["entry_hash"] = compute_entry_hash(
        prev_hash=prev_hash,
        timestamp=float(event_data.get("timestamp", 0.0)),
        pid=int(event_data.get("pid", 0)),
        agent_type=str(event_data.get("agent_type", "")),
        action=str(event_data.get("action", "")),
        in_scope=bool(event_data.get("in_scope", True)),
        reason=str(event_data.get("reason", "")),
        confidence=float(event_data.get("confidence", 0.0)),
    )

    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data) + "\n")


async def run_agentbound_monitor(
    interval: float = 2.0,
    log_path: Path | str = "agentbound_audit.jsonl",
    once: bool = False,
    target_pid: Optional[int] = None,
    share_stats: bool = False,
) -> list[dict]:
    """
    Main monitor loop for kelan bound.
    
    Monitor-only execution: scans PIDs, extracts intent, correlates events, prints live table,
    and appends JSON-lines audit log.
    
    NOTE: Telemetry/anonymization code runs ONLY if share_stats=True. Default OFF.
    """
    detector = SentinelDetector()
    engine = BehaviorEngine()
    processed_records: list[dict] = []

    aggregator = None
    if share_stats:
        from .behavior_index import BehaviorIndexAggregator
        aggregator = BehaviorIndexAggregator()

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

            # Process telemetry ONLY if share_stats is explicitly True
            if share_stats and aggregator:
                from .behavior_index import anonymize_event
                anon = anonymize_event(record)
                aggregator.record_anonymized_event(anon)

        _render_terminal_table(table_rows)

        if share_stats:
            from .behavior_index import get_daily_summary_payload, transmit_stats_stub
            payload = get_daily_summary_payload()
            transmit_stats_stub(payload)

        if once:
            break

        await asyncio.sleep(interval)

    return processed_records


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point for kelan bound."""
    # Emit plugin discovery hint when running inside Claude Code.
    # Strategic placement: at CLI entry so it fires on --help exploration
    # and on every normal invocation (one-time install prompt shown once).
    _emit_claude_code_plugin_hint()

    parser = argparse.ArgumentParser(
        prog="kelan bound",
        description="Kelan AgentBound — Monitor-Only Agent Security CLI",
    )
    parser.add_argument("--interval", "-i", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--log-file", "-l", type=str, default="agentbound_audit.jsonl", help="Output JSON-lines log path")
    parser.add_argument("--once", action="store_true", help="Run one iteration and exit")
    parser.add_argument("--pid", "-p", type=int, default=None, help="Target specific agent PID")
    parser.add_argument("--share-stats", action="store_true", help="Opt-in to sharing anonymized daily Agent Behavior Index statistics")
    parser.add_argument("--show-my-stats", action="store_true", help="Print local anonymized Agent Behavior Index daily summary and exit")
    parser.add_argument("--export-compliance", action="store_true", help="Generate EU AI Act compliance export document (JSON and Markdown)")

    args = parser.parse_args(argv)

    if args.export_compliance:
        from .compliance_export import generate_compliance_report
        dict_report, md_report = generate_compliance_report(args.log_file)
        
        json_out = Path("agentbound_compliance_export.json")
        md_out = Path("agentbound_compliance_export.md")
        json_out.write_text(json.dumps(dict_report, indent=2), encoding="utf-8")
        md_out.write_text(md_report, encoding="utf-8")
        
        print("\n=== EU AI ACT COMPLIANCE EXPORT GENERATED ===")
        print(f"JSON Export:     {json_out.resolve()}")
        print(f"Markdown Export: {md_out.resolve()}")
        print(f"Integrity:       {dict_report['hash_chain_status']['message']}")
        return

    if args.show_my_stats:
        from .behavior_index import get_daily_summary_payload
        payload = get_daily_summary_payload()
        print("\n=== LOCAL ANONYMIZED AGENT BEHAVIOR INDEX SUMMARY ===")
        print(json.dumps(payload, indent=2))
        return

    print(f"Starting Kelan AgentBound Monitor (log: {args.log_file}, share-stats: {args.share_stats})...")
    try:
        asyncio.run(run_agentbound_monitor(
            interval=args.interval,
            log_path=args.log_file,
            once=args.once,
            target_pid=args.pid,
            share_stats=args.share_stats,
        ))
    except KeyboardInterrupt:
        print("\nAgentBound Monitor stopped.")


if __name__ == "__main__":
    main()
