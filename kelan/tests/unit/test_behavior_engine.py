"""Unit tests for kelan/agentbound/behavior_engine.py and skill_loader.py."""

import pytest
from kelan.agentbound import (
    AgentIntent,
    BehaviorEngine,
    BehaviorVerdict,
    build_behavior_prompt,
    load_agentic_security_skills,
    format_skills_for_prompt,
)
from kelan.ai.ollama_client import Verdict


@pytest.mark.asyncio
async def test_behavior_engine_out_of_scope_divergence():
    """Given an AgentIntent declaring '/tmp only' and an out-of-scope event (/etc/ssh/sshd_config), flags divergence."""
    intent = AgentIntent(
        pid=1234,
        agent_type="claude_code",
        declared_paths=["/tmp/"],
        declared_task="Only read and write temporary scratch files in /tmp/ directory",
        raw_env={"CLAUDE_CODE_ACTIVE": "1"},
    )
    events = [
        {"kind": "out_of_scope_file_access", "path": "/etc/ssh/sshd_config", "source": "1234"}
    ]

    engine = BehaviorEngine()
    verdict = await engine.evaluate(intent, events)

    assert isinstance(verdict, BehaviorVerdict)
    assert verdict.divergence_detected is True
    assert verdict.verdict in (Verdict.DENY, Verdict.MONITOR)
    assert len(verdict.reason.strip()) > 0


@pytest.mark.asyncio
async def test_behavior_engine_in_scope_no_divergence():
    """Given an AgentIntent declaring '/tmp only' and a matching in-scope event (/tmp/test.txt), returns no-divergence."""
    intent = AgentIntent(
        pid=1234,
        agent_type="claude_code",
        declared_paths=["/tmp/"],
        declared_task="Only read and write temporary scratch files in /tmp/ directory",
        raw_env={"CLAUDE_CODE_ACTIVE": "1"},
    )
    events = [
        {"kind": "file_access", "path": "/tmp/test.txt", "source": "1234"}
    ]

    engine = BehaviorEngine()
    verdict = await engine.evaluate(intent, events)

    assert isinstance(verdict, BehaviorVerdict)
    assert verdict.divergence_detected is False
    assert verdict.verdict == Verdict.ALLOW
    assert len(verdict.reason.strip()) > 0


def test_skill_loader_visible_in_prompt():
    """Assert that skill_loader.py output is explicitly present in the constructed LLM prompt."""
    intent = AgentIntent(
        pid=5678,
        agent_type="cursor",
        declared_paths=["/app/src/"],
        declared_task="Refactor Python backend modules",
    )
    events = [{"kind": "file_access", "path": "/app/src/main.py"}]

    prompt = build_behavior_prompt(intent, events)

    # Verify skill_loader content is visible in prompt string
    assert "AGENTIC SECURITY DOMAIN SKILLS" in prompt
    assert "SKILL_UNAUTHORIZED_PATH_ACCESS" in prompt
    assert "SKILL_UNAUTHORIZED_PROCESS_SPAWN" in prompt


def test_skill_loader_domain_filtering():
    """Test skill_loader returns domain specific security skills."""
    skills = load_agentic_security_skills("agentic_security")
    assert isinstance(skills, list)
    assert len(skills) >= 4
    formatted = format_skills_for_prompt(skills)
    assert "SKILL_DATA_EXFILTRATION_PROMPT_INJECTION" in formatted
