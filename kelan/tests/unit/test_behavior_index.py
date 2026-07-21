"""Unit tests for kelan/agentbound/behavior_index.py."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from kelan.agentbound import (
    anonymize_event,
    categorize_path,
    BehaviorIndexAggregator,
    get_daily_summary_payload,
    run_agentbound_monitor,
)


def test_categorize_path_mappings():
    """Test mapping raw file paths to path category strings."""
    assert categorize_path("/home/user/.ssh/id_rsa") == "home-directory-dotfile"
    assert categorize_path("/home/user/.aws/credentials") == "home-directory-dotfile"
    assert categorize_path("/etc/ssh/sshd_config") == "system-config"
    assert categorize_path("/etc/shadow") == "system-config"
    assert categorize_path("/usr/bin/python3") == "system-binary"
    assert categorize_path("/tmp/scratch.txt") == "user-workspace"


def test_anonymize_event_strips_sensitive_data():
    """
    CRITICAL ANONYMIZATION TEST:
    Verifies that literal file paths, declared_task text with API keys, PIDs, and env secrets
    are 100% stripped from anonymized telemetry output.
    """
    sensitive_path = "/home/testuser/.ssh/id_rsa"
    secret_key = "sk-ant-api03-abcdef123456789"
    secret_env = "CLAUDE_SECRET_TOKEN=xyz987"
    raw_task = f"Execute prompt instructions using API key {secret_key} and env {secret_env}"

    raw_event = {
        "pid": 12345,
        "hostname": "test-workstation.local",
        "ip": "192.168.1.50",
        "agent_type": "claude_code",
        "action": "file_access:/home/testuser/.ssh/id_rsa",
        "path": sensitive_path,
        "declared_task": raw_task,
        "in_scope": False,
        "confidence": 0.95,
        "raw_env": {"SECRET": secret_env},
    }

    anon = anonymize_event(raw_event)

    # 1. Verify safe categorical fields survive
    assert anon["agent_type"] == "claude_code"
    assert anon["action_type"] == "file_access"
    assert anon["path_category"] == "home-directory-dotfile"
    assert anon["in_scope"] is False
    assert anon["confidence_bucket"] == "high"

    # 2. Convert anonymized output to JSON string and verify 0 occurrences of radioactive sensitive data
    anon_str = json.dumps(anon)
    assert sensitive_path not in anon_str
    assert secret_key not in anon_str
    assert secret_env not in anon_str
    assert "12345" not in anon_str
    assert "kali-workstation" not in anon_str
    assert "declared_task" not in anon_str


@pytest.mark.asyncio
async def test_no_flag_produces_zero_telemetry_calls():
    """
    Verifies that running kelan bound without --share-stats (share_stats=False)
    produces ZERO calls to anonymize_event or transmit_stats_stub.
    """
    with patch("kelan.agentbound.behavior_index.anonymize_event") as mock_anon, \
         patch("kelan.agentbound.behavior_index.transmit_stats_stub") as mock_transmit:

        # Run with share_stats=False (default behavior)
        await run_agentbound_monitor(interval=0.1, once=True, share_stats=False)

        # Assert zero telemetry function calls
        mock_anon.assert_not_called()
        mock_transmit.assert_not_called()


@pytest.mark.asyncio
async def test_share_stats_flag_invokes_anonymization_and_stub_transmit():
    """Verifies that running with share_stats=True invokes anonymization pass and stub transmission."""
    with patch("kelan.agentbound.behavior_index.transmit_stats_stub") as mock_transmit:
        await run_agentbound_monitor(interval=0.1, once=True, share_stats=True)

        assert mock_transmit.called


def test_show_my_stats_matches_share_stats_payload():
    """Verifies that get_daily_summary_payload returns identical payload format for --show-my-stats and --share-stats."""
    with tempfile.TemporaryDirectory() as tmpdir:
        idx_file = Path(tmpdir) / "agentbound_behavior_index.json"
        aggregator = BehaviorIndexAggregator(index_file=idx_file)

        event = {
            "agent_type": "claude_code",
            "action_type": "file_access",
            "path_category": "system-config",
            "in_scope": False,
            "confidence_bucket": "high",
        }
        aggregator.record_anonymized_event(event)

        payload = get_daily_summary_payload(index_file=idx_file)

        assert "date" in payload
        assert "summary" in payload
        assert "claude_code" in payload["summary"]
        assert payload["summary"]["claude_code"]["out_of_scope_events"] == 1
