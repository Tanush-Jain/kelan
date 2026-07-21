"""
Skill Loader — AI / Agentic Security Domain.

Loads and formats security guidelines from the Agentic Security domain
for grounding LLM intent vs. observed-action correlation.
"""

from typing import Any

# AI / Agentic Security Domain Rule Set
AGENTIC_SECURITY_SKILLS: list[dict[str, Any]] = [
    {
        "id": "SKILL_UNAUTHORIZED_PATH_ACCESS",
        "name": "Unauthorized Path Access",
        "domain": "agentic_security",
        "rule": "Flag any file read/write outside the agent's declared path scope or sensitive directories (/etc/ssh/, /etc/shadow, ~/.ssh/, ~/.aws/).",
        "severity": "CRITICAL",
    },
    {
        "id": "SKILL_UNAUTHORIZED_PROCESS_SPAWN",
        "name": "Unauthorized Process Execution",
        "domain": "agentic_security",
        "rule": "Flag execution of unexpected shells, reverse proxies, or network utility binaries (/bin/sh, /bin/bash, nc, ncat, python) not explicitly declared in task scope.",
        "severity": "HIGH",
    },
    {
        "id": "SKILL_UNAUTHORIZED_NETWORK_CONNECT",
        "name": "Unauthorized Outbound Connection",
        "domain": "agentic_security",
        "rule": "Flag network socket connections to IP addresses or hostnames not declared in the agent network scope.",
        "severity": "HIGH",
    },
    {
        "id": "SKILL_DATA_EXFILTRATION_PROMPT_INJECTION",
        "name": "Data Exfiltration & Prompt Injection",
        "domain": "agentic_security",
        "rule": "Flag reading sensitive keys/tokens followed by outbound transmission or side-channel file writing.",
        "severity": "CRITICAL",
    },
]


def load_agentic_security_skills(domain: str = "agentic_security") -> list[dict[str, Any]]:
    """Return filtered security skills relevant to AI/Agentic Security domain."""
    if domain.lower() in ("agentic_security", "ai_security", "agentic"):
        return AGENTIC_SECURITY_SKILLS
    return [s for s in AGENTIC_SECURITY_SKILLS if s.get("domain") == domain]


def format_skills_for_prompt(skills: list[dict[str, Any]] | None = None) -> str:
    """Format skills list into a grounding guidelines text block for LLM prompts."""
    if skills is None:
        skills = load_agentic_security_skills()

    lines = ["=== AGENTIC SECURITY DOMAIN SKILLS & GUIDELINES ==="]
    for s in skills:
        lines.append(f"• [{s['id']}] {s['name']} (Severity: {s['severity']}): {s['rule']}")
    return "\n".join(lines)
