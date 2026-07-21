"""Unit tests for kelan/agentbound/cli.py."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest

from kelan.agentbound import run_agentbound_monitor


@pytest.mark.asyncio
async def test_agentbound_cli_mock_agent_run():
    """Test kelan bound monitor execution against a mock agent process."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "agentbound_audit.jsonl"
        task_file = Path(tmpdir) / "CLAUDE.md"
        task_file.write_text("Mock agent scope: read /tmp data only")

        env = dict(os.environ)
        env["CLAUDE_CODE_MOCK_SESSION"] = "test_bound_123"

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            env=env,
            cwd=tmpdir,
        )

        try:
            pid = proc.pid
            records = await run_agentbound_monitor(
                interval=0.1,
                log_path=log_file,
                once=True,
                target_pid=pid,
            )

            assert len(records) > 0
            rec = records[0]
            assert rec["pid"] == pid
            assert rec["agent_type"] == "claude_code"
            assert "in_scope" in rec
            assert "reason" in rec
            assert "confidence" in rec

            # Verify JSON-lines log file content
            assert log_file.exists()
            lines = [line.strip() for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            assert len(lines) > 0

            parsed = json.loads(lines[0])
            assert parsed["pid"] == pid
            assert parsed["agent_type"] == "claude_code"
            assert "timestamp" in parsed
            assert "in_scope" in parsed
            assert "reason" in parsed
            assert "confidence" in parsed
        finally:
            proc.terminate()
            proc.wait()


def test_no_enforcement_code_in_cli():
    """Assert that kelan/agentbound/cli.py contains ZERO enforcement/blocking code paths."""
    cli_path = Path(__file__).parent.parent.parent / "agentbound" / "cli.py"
    assert cli_path.exists()

    content = cli_path.read_text(encoding="utf-8").lower()

    # Assert strict monitor-only guarantees
    forbidden_terms = ["revoke", "permit", "lsm_hook", "block_process", "drop_packet", "enforce_rule"]
    for term in forbidden_terms:
        assert term not in content, f"Forbidden enforcement term '{term}' found in cli.py"
