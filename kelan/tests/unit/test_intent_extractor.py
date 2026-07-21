"""Unit tests for kelan/agentbound/intent_extractor.py."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from kelan.agentbound import AgentIntent, extract_intent, read_proc_environ, probe_task_files


def test_intent_extractor_mock_agent_process():
    """Test extracting intent from a mock agent process with env vars and a sample task file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        task_file = tmp_path / "CLAUDE.md"
        task_file.write_text("Agent task instructions: only read /tmp/data and /home/user/logs")

        # Spawn a python process with CLAUDE_CODE_* environment variable set
        env = dict(os.environ)
        env["CLAUDE_CODE_TEST_KEY"] = "active_agent_session_123"
        env["ANTHROPIC_API_KEY"] = "sk-ant-test-key"

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            env=env,
            cwd=tmpdir,
        )

        try:
            pid = proc.pid
            intent = extract_intent(pid, working_dir_override=tmpdir)

            assert isinstance(intent, AgentIntent)
            assert intent.pid == pid
            assert intent.agent_type == "claude_code"
            assert intent.declared_task is not None
            assert "only read /tmp/data" in intent.declared_task
            assert "CLAUDE_CODE_TEST_KEY" in intent.raw_env
            assert "/tmp/data" in intent.declared_paths or "/home/user/logs" in intent.declared_paths
        finally:
            proc.terminate()
            proc.wait()


def test_intent_extractor_nothing_found_returns_empty():
    """Explicit unit test for the 'nothing found' case (non-existent PID) — returns empty AgentIntent without raising."""
    invalid_pid = 999999
    intent = extract_intent(invalid_pid)

    assert isinstance(intent, AgentIntent)
    assert intent.pid == invalid_pid
    assert intent.agent_type == "unknown"
    assert intent.declared_paths == []
    assert intent.declared_task is None
    assert intent.raw_env == {}


def test_probe_task_files_finds_candidates():
    """Test task file discovery across common candidate filenames."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "task.md").write_text("Sample task instructions for agent")

        declared_task, found_files = probe_task_files(tmp_path)
        assert declared_task is not None
        assert "task.md" in found_files
        assert "Sample task instructions" in declared_task
