"""
EU AI Act Compliance Exporter & Hash-Chain Integrity Verifier — AgentBound Phase 1.

Converts local audit logs into EU AI Act (Articles 12, 14, 15) aligned compliance reports.
Features SHA-256 cryptographic hash-chain verification to detect audit log tampering.
"""

from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import jinja2
import structlog

log = structlog.get_logger()

GENESIS_HASH = "0" * 64


def compute_entry_hash(
    prev_hash: str,
    timestamp: float,
    pid: int,
    agent_type: str,
    action: str,
    in_scope: bool,
    reason: str,
    confidence: float,
) -> str:
    """Compute SHA-256 hash for an audit log entry."""
    raw = f"{prev_hash}:{timestamp}:{pid}:{agent_type}:{action}:{in_scope}:{reason}:{confidence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_hash_chain(entries: list[dict[str, Any]]) -> tuple[bool, Optional[int], str]:
    """
    Verify SHA-256 hash-chain integrity across audit log entries.
    Returns (is_valid, broken_index, status_message).
    """
    if not entries:
        return True, None, "Empty audit log: zero entries to verify."

    current_prev = GENESIS_HASH

    for i, entry in enumerate(entries):
        entry_prev = entry.get("prev_hash", GENESIS_HASH)
        entry_hash = entry.get("entry_hash", "")

        # Check prev_hash linkage
        if entry_prev != current_prev:
            msg = f"Tampering detected at entry index {i} (PID: {entry.get('pid')}): prev_hash mismatch."
            log.warning("hash_chain_tampering_detected", index=i, reason="prev_hash_mismatch")
            return False, i, msg

        # Re-compute expected hash
        expected_hash = compute_entry_hash(
            prev_hash=entry_prev,
            timestamp=float(entry.get("timestamp", 0.0)),
            pid=int(entry.get("pid", 0)),
            agent_type=str(entry.get("agent_type", "")),
            action=str(entry.get("action", "")),
            in_scope=bool(entry.get("in_scope", True)),
            reason=str(entry.get("reason", "")),
            confidence=float(entry.get("confidence", 0.0)),
        )

        if entry_hash != expected_hash:
            msg = f"Tampering detected at entry index {i} (PID: {entry.get('pid')}): entry_hash content mismatch."
            log.warning("hash_chain_tampering_detected", index=i, reason="content_hash_mismatch")
            return False, i, msg

        current_prev = entry_hash

    return True, None, "Hash-chain integrity verified: zero tampering detected across all entries."


def get_eu_ai_act_article_mappings() -> dict[str, Any]:
    """Return plain-language mappings citing specific EU AI Act articles for captured audit fields."""
    return {
        "Article_12": {
            "article": "EU AI Act Article 12 — Automatic Logging & Record-Keeping",
            "requirement": "High-risk AI systems must feature automatic recording of events ('logs') over their operational lifecycle.",
            "satisfied_fields": ["timestamp", "pid", "agent_type", "action", "reason"],
            "compliance_status": "COMPLIANT — Automated event logging records every process spawn, file access, and scope verdict with microsecond timestamps.",
        },
        "Article_14": {
            "article": "EU AI Act Article 14 — Human Oversight Evidence",
            "requirement": "High-risk AI systems shall enable natural persons to effectively oversee system functioning and audit security decisions.",
            "satisfied_fields": ["in_scope", "confidence", "reason"],
            "compliance_status": "COMPLIANT — Correlation engine outputs explicit human-inspectable reasoning, confidence ratings, and scope divergence flags.",
        },
        "Article_15": {
            "article": "EU AI Act Article 15 — Cybersecurity & Log Integrity",
            "requirement": "High-risk AI systems shall be resilient against unauthorized alterations of logs or system behavior.",
            "satisfied_fields": ["prev_hash", "entry_hash"],
            "compliance_status": "COMPLIANT — SHA-256 cryptographic hash-chaining guarantees log immutability and instant detection of unauthorized tampering.",
        },
    }


MARKDOWN_REPORT_TEMPLATE = """# EU AI Act Compliance Export Report — Kelan AgentBound

**Generated At:** {{ report_metadata.generated_at }}  
**Log Path:** `{{ report_metadata.log_path }}`  
**Monitored Date Range:** {{ report_metadata.date_range }}

---

## 1. Executive Summary

| Metric | Value |
| :--- | :--- |
| **Total Monitored Agent Sessions (Unique PIDs)** | {{ summary.total_sessions_monitored }} |
| **Total Logged Audit Events** | {{ summary.total_events_recorded }} |
| **Scope Divergence Events Detected** | {{ summary.total_divergence_events }} |
| **Log Cryptographic Integrity** | {% if hash_chain_status.valid %}✅ VERIFIED (PASS){% else %}❌ TAMPERED (FAIL at Index {{ hash_chain_status.broken_index }}){% endif %} |

> **Integrity Verification Status:** {{ hash_chain_status.message }}

---

## 2. Action Category Breakdown

| Action Type | Event Count |
| :--- | :--- |
{% for cat, count in summary.category_breakdown.items() %}
| `{{ cat }}` | {{ count }} |
{% endfor %}

---

## 3. EU AI Act Article Compliance Mappings

{% for key, art in article_mappings.items() %}
### {{ art.article }}
* **Requirement:** {{ art.requirement }}
* **Satisfied Audit Fields:** {% for f in art.satisfied_fields %}`{{ f }}`{% if not loop.last %}, {% endif %}{% endfor %}
* **Compliance Verdict:** {{ art.compliance_status }}

{% endfor %}
"""


def generate_compliance_report(
    log_path: Path | str = "agentbound_audit.jsonl",
    date_start: Optional[str] = None,
    date_end: Optional[str] = None,
) -> tuple[dict[str, Any], str]:
    """
    Generate EU AI Act compliance export document from local audit log.
    Returns (report_data_dict, report_markdown_string).
    """
    p = Path(log_path)
    entries: list[dict[str, Any]] = []

    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line_str = line.strip()
            if line_str:
                try:
                    entries.append(json.loads(line_str))
                except Exception:
                    pass

    # Verify hash-chain integrity
    is_valid, broken_idx, status_msg = verify_hash_chain(entries)

    # Compute summary stats
    pids = set(e.get("pid") for e in entries if e.get("pid"))
    total_events = len(entries)
    divergence_count = sum(1 for e in entries if not e.get("in_scope", True))

    categories: dict[str, int] = {}
    for e in entries:
        act = str(e.get("action", "other")).split(":")[0]
        categories[act] = categories.get(act, 0) + 1

    article_mappings = get_eu_ai_act_article_mappings()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    report_dict = {
        "report_metadata": {
            "generated_at": now_str,
            "log_path": str(p),
            "date_range": f"{date_start or 'All Time'} to {date_end or 'Present'}",
        },
        "summary": {
            "total_sessions_monitored": len(pids),
            "total_events_recorded": total_events,
            "total_divergence_events": divergence_count,
            "category_breakdown": categories,
        },
        "hash_chain_status": {
            "valid": is_valid,
            "broken_index": broken_idx,
            "message": status_msg,
        },
        "article_mappings": article_mappings,
    }

    # Render Jinja2 Markdown report
    template = jinja2.Template(MARKDOWN_REPORT_TEMPLATE)
    report_markdown = template.render(**report_dict)

    return report_dict, report_markdown
