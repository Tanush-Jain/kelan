"""Unit tests for kelan/agentbound/compliance_export.py."""

import json
import tempfile
from pathlib import Path
import pytest

from kelan.agentbound import (
    append_json_line,
    compute_entry_hash,
    generate_compliance_report,
    get_eu_ai_act_article_mappings,
    verify_hash_chain,
)


def test_hash_chain_valid_on_clean_log():
    """Verify that append_json_line creates valid SHA-256 hash-chained entries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"

        for i in range(5):
            record = {
                "timestamp": 1700000000.0 + i,
                "pid": 1000 + i,
                "agent_type": "claude_code",
                "action": f"file_access:/tmp/file_{i}.txt",
                "in_scope": True,
                "reason": "In-scope file access",
                "confidence": 0.95,
            }
            append_json_line(log_path, record)

        entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        assert len(entries) == 5

        is_valid, broken_idx, msg = verify_hash_chain(entries)
        assert is_valid is True
        assert broken_idx is None
        assert "zero tampering detected" in msg.lower()


def test_hash_chain_tampering_detected():
    """
    CRITICAL SUCCESS CRITERION:
    Given a synthetic audit log with one deliberately tampered entry at index 2,
    verify_hash_chain and generate_compliance_report correctly flag hash-chain verification
    failure at the EXACT broken entry index 2.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"

        # Generate 5 valid chained entries
        for i in range(5):
            record = {
                "timestamp": 1700000000.0 + i,
                "pid": 2000 + i,
                "agent_type": "claude_code",
                "action": f"file_access:/home/user/doc_{i}.txt",
                "in_scope": True,
                "reason": "Normal file access",
                "confidence": 0.90,
            }
            append_json_line(log_path, record)

        lines = log_path.read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in lines]

        # Deliberately tamper entry at index 2 (modify action string)
        entries[2]["action"] = "file_access:/etc/shadow"

        # Write tampered lines back
        log_path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

        # Verify hash-chain verification flags failure at exact index 2
        is_valid, broken_idx, msg = verify_hash_chain(entries)
        assert is_valid is False
        assert broken_idx == 2
        assert "Tampering detected at entry index 2" in msg

        # Verify generate_compliance_report report dict reflects failure
        report_dict, md_report = generate_compliance_report(log_path)
        assert report_dict["hash_chain_status"]["valid"] is False
        assert report_dict["hash_chain_status"]["broken_index"] == 2
        assert "TAMPERED (FAIL at Index 2)" in md_report


def test_compliance_export_clean_log_articles():
    """
    CRITICAL SUCCESS CRITERION:
    Given a clean log, export produces a document with non-empty, correctly-cited
    article mappings for at least Art. 12, Art. 14, and Art. 15.
    """
    mappings = get_eu_ai_act_article_mappings()
    assert "Article_12" in mappings
    assert "Article_14" in mappings
    assert "Article_15" in mappings

    assert "Article 12" in mappings["Article_12"]["article"]
    assert "Article 14" in mappings["Article_14"]["article"]
    assert "Article 15" in mappings["Article_15"]["article"]

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        record = {
            "timestamp": 1700000000.0,
            "pid": 3000,
            "agent_type": "claude_code",
            "action": "network_connect:api.anthropic.com",
            "in_scope": True,
            "reason": "Authorized endpoint",
            "confidence": 0.99,
        }
        append_json_line(log_path, record)

        report_dict, md_report = generate_compliance_report(log_path)

        assert report_dict["hash_chain_status"]["valid"] is True
        assert report_dict["summary"]["total_events_recorded"] == 1

        # Check Jinja2 rendered Markdown contains citations
        assert "EU AI Act Article 12 — Automatic Logging" in md_report
        assert "EU AI Act Article 14 — Human Oversight" in md_report
        assert "EU AI Act Article 15 — Cybersecurity" in md_report
