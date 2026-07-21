"""
Agent Behavior Index Telemetry Aggregator — AgentBound Phase 1.

Opt-in, anonymized local telemetry aggregator that turns per-user audit logs
into shareable, aggregate statistics for a public Agent Behavior Index.

GUARANTEES:
1. Opt-in only (--share-stats). Default OFF.
2. 100% anonymized BEFORE aggregation: strips PIDs, hostnames, literal paths, env vars, and declared_task free text.
3. Transmits ONLY daily categorical summaries, never raw events.
"""

from __future__ import annotations
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import structlog

log = structlog.get_logger()

DEFAULT_INDEX_FILE = "agentbound_behavior_index.json"
DEFAULT_TELEMETRY_ENDPOINT = "https://api.kelan.security/v1/telemetry/index"


def categorize_path(path_str: str) -> str:
    """
    Map raw file path to a path category string.
    NEVER returns the raw literal file path.
    """
    if not path_str:
        return "none"

    p = path_str.lower()
    
    # Dotfiles and sensitive user credentials
    if any(k in p for k in ("/.ssh", "/.aws", "/.env", ".bashrc", ".zshrc", "/.cursor", "/.claude")):
        return "home-directory-dotfile"
        
    # System configuration files
    if p.startswith("/etc/") or p.startswith("/var/etc/"):
        return "system-config"
        
    # System binary executables
    if any(p.startswith(b) for b in ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/")):
        return "system-binary"
        
    # User workspace or temp directories
    if any(k in p for k in ("/home/", "/tmp/", "/var/tmp/", "/app/")):
        return "user-workspace"

    return "other"


def anonymize_event(event_data: dict[str, Any]) -> dict[str, Any]:
    """
    ANONYMIZATION PASS BEFORE AGGREGATION.
    
    Completely strips:
    - PIDs, hostnames, IPs, source addresses
    - Raw literal file paths (replaced with path_category ONLY)
    - Secret tokens or API keys matching common patterns
    - declared_task free text (treated as radioactive)
    
    Returns ONLY safe categorical fields.
    """
    agent_type = str(event_data.get("agent_type", "unknown"))
    
    # Classify action type
    raw_action = str(event_data.get("action", event_data.get("kind", "other"))).lower()
    if "file" in raw_action or "open" in raw_action:
        action_type = "file_access"
    elif "connect" in raw_action or "network" in raw_action:
        action_type = "network_connect"
    elif "exec" in raw_action or "spawn" in raw_action or "process" in raw_action:
        action_type = "process_exec"
    else:
        action_type = "other"

    # Categorize path (raw path is discarded)
    raw_path = str(event_data.get("path", event_data.get("target", "")))
    path_cat = categorize_path(raw_path)

    # In-scope boolean
    in_scope = bool(event_data.get("in_scope", True))

    # Confidence bucket
    raw_conf = float(event_data.get("confidence", 0.5))
    if raw_conf >= 0.8:
        conf_bucket = "high"
    elif raw_conf >= 0.5:
        conf_bucket = "medium"
    else:
        conf_bucket = "low"

    return {
        "agent_type": agent_type,
        "action_type": action_type,
        "path_category": path_cat,
        "in_scope": in_scope,
        "confidence_bucket": conf_bucket,
    }


class BehaviorIndexAggregator:
    """Local aggregator rolling up anonymized events into daily summary counters."""

    def __init__(self, index_file: Path | str = DEFAULT_INDEX_FILE) -> None:
        self.index_file = Path(index_file)

    def _load_data(self) -> dict[str, Any]:
        if not self.index_file.exists():
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return {"date": today, "summary": {}}

        try:
            return json.loads(self.index_file.read_text(encoding="utf-8"))
        except Exception:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return {"date": today, "summary": {}}

    def _save_data(self, data: dict[str, Any]) -> None:
        self.index_file.parent.mkdir(parents=True, exist_ok=True)
        self.index_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def record_anonymized_event(self, anon_event: dict[str, Any]) -> None:
        """Record a single anonymized event into daily aggregate counters."""
        data = self._load_data()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if data.get("date") != today:
            data = {"date": today, "summary": {}}

        summary = data.setdefault("summary", {})
        atype = anon_event["agent_type"]
        entry = summary.setdefault(atype, {
            "total_events": 0,
            "in_scope_events": 0,
            "out_of_scope_events": 0,
            "categories": {},
            "action_types": {},
            "confidence_buckets": {},
        })

        entry["total_events"] += 1
        if anon_event["in_scope"]:
            entry["in_scope_events"] += 1
        else:
            entry["out_of_scope_events"] += 1

        pcat = anon_event["path_category"]
        entry["categories"][pcat] = entry["categories"].get(pcat, 0) + 1

        act = anon_event["action_type"]
        entry["action_types"][act] = entry["action_types"].get(act, 0) + 1

        cb = anon_event["confidence_bucket"]
        entry["confidence_buckets"][cb] = entry["confidence_buckets"].get(cb, 0) + 1

        self._save_data(data)


def get_daily_summary_payload(index_file: Path | str = DEFAULT_INDEX_FILE) -> dict[str, Any]:
    """Return the exact anonymized daily aggregate summary dict for inspection or transmission."""
    p = Path(index_file)
    if not p.exists():
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return {"date": today, "summary": {}}

    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return {"date": today, "summary": {}}


def transmit_stats_stub(
    summary_payload: dict[str, Any],
    endpoint_url: str = DEFAULT_TELEMETRY_ENDPOINT,
) -> bool:
    """
    STUB TRANSMISSION ENDPOINT.
    
    Logs locally what WOULD be sent to the public Agent Behavior Index endpoint.
    No real ingestion server infrastructure is called.
    """
    log.info(
        "behavior_index_telemetry_stub_transmit",
        endpoint=endpoint_url,
        date=summary_payload.get("date"),
        agents_count=len(summary_payload.get("summary", {})),
    )
    print(f"\n[STUB TELEMETRY POST] Would transmit daily summary to {endpoint_url}:")
    print(json.dumps(summary_payload, indent=2))
    return True
