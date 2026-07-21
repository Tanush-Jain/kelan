"""
Agent Intent Extractor — AgentBound Phase 1.

Given a discovered agent process PID, extracts declared intent by inspecting:
1. Process environment variables via /proc/<pid>/environ.
2. System prompts, task files, and AGENTS.md / CLAUDE.md in process working directory.
3. Best-effort heuristic path extraction from prompt text.
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import structlog

log = structlog.get_logger()


@dataclass
class AgentIntent:
    pid:            int
    agent_type:     str
    declared_paths: list[str]     = field(default_factory=list)
    declared_task:  Optional[str] = None
    raw_env:        dict[str, str] = field(default_factory=dict)


def read_proc_environ(pid: int) -> dict[str, str]:
    """Read process environment variables defensively from /proc/<pid>/environ."""
    env_path = Path(f"/proc/{pid}/environ")
    if not env_path.exists():
        return {}

    try:
        raw_bytes = env_path.read_bytes()
        env_dict: dict[str, str] = {}
        for entry in raw_bytes.split(b"\x00"):
            if b"=" in entry:
                key, val = entry.split(b"=", 1)
                k = key.decode("utf-8", errors="replace")
                v = val.decode("utf-8", errors="replace")
                env_dict[k] = v

        # Log detected agent signals
        agent_keys = [k for k in env_dict if any(k.startswith(p) for p in ("CLAUDE_", "CURSOR_", "ANTHROPIC_", "OPENAI_"))]
        if agent_keys:
            log.info("intent_extractor_env_signals_found", pid=pid, keys=agent_keys)

        return env_dict
    except Exception as exc:
        log.debug("read_proc_environ_failed", pid=pid, error=str(exc))
        return {}


def get_proc_cwd(pid: int) -> Optional[Path]:
    """Resolve process current working directory from /proc/<pid>/cwd."""
    try:
        cwd_link = Path(f"/proc/{pid}/cwd")
        if cwd_link.exists():
            return cwd_link.resolve()
    except Exception as exc:
        log.debug("get_proc_cwd_failed", pid=pid, error=str(exc))
    return None


def _detect_agent_type(env: dict[str, str], task_files_found: list[str]) -> str:
    """Classify agent type based on environment signals and workspace files."""
    env_keys = set(env.keys())
    if any(k.startswith("CLAUDE_CODE_") for k in env_keys) or "ANTHROPIC_API_KEY" in env_keys or any("CLAUDE.md" in f for f in task_files_found):
        return "claude_code"
    if any(k.startswith("CURSOR_") for k in env_keys) or any(".cursor" in f for f in task_files_found):
        return "cursor"
    if any(k.startswith("OPENAI_") or k.startswith("CODEX_") for k in env_keys):
        return "openai_agent"
    if env:
        return "generic_agent"
    return "unknown"


def _extract_heuristic_paths(text: str) -> list[str]:
    """
    BEST-EFFORT HEURISTIC PATH EXTRACTION.
    
    NOTE: Best-effort regex extraction from prompt text is explicitly the weakest,
    most heuristic layer of the entire pipeline. It serves only as an initial
    fallback for scope bounds and must be validated downstream against actual syscalls.
    """
    if not text:
        return []

    # Regex matches absolute paths (/foo/bar) and home relative paths (~/foo)
    pattern = r'(?:/[a-zA-Z0-9_.-]+)+|(?:~/[a-zA-Z0-9_.-]+)+'
    matches = re.findall(pattern, text)
    
    # Clean and deduplicate while preserving order
    seen = set()
    cleaned = []
    for m in matches:
        # Exclude common false positives like URLs or trailing dots
        p = m.rstrip(".,;:)'\"")
        if p and p not in seen and len(p) > 1:
            seen.add(p)
            cleaned.append(p)
            
    return cleaned


def probe_task_files(cwd: Path) -> tuple[Optional[str], list[str]]:
    """Probe common task file locations in workspace."""
    if not cwd or not cwd.exists():
        return None, []

    candidates = [
        "CLAUDE.md",
        ".claude/task.md",
        ".claude/prompt.txt",
        ".cursorrules",
        ".cursor/rules",
        "AGENTS.md",
        "task.md",
        "prompt.txt",
    ]

    contents = []
    found_files = []

    for rel in candidates:
        target = cwd / rel
        if target.exists() and target.is_file():
            try:
                text = target.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    contents.append(f"--- File: {rel} ---\n{text}")
                    found_files.append(rel)
            except Exception:
                pass

    declared_task = "\n\n".join(contents) if contents else None
    return declared_task, found_files


def extract_intent(pid: int, working_dir_override: Optional[Path | str] = None) -> AgentIntent:
    """
    Main public API for intent extraction.
    
    Given a PID, inspects /proc/<pid>/environ and workspace task files.
    Always returns an AgentIntent instance (defensive fallback on unreadable PID).
    """
    try:
        env = read_proc_environ(pid)
        cwd = Path(working_dir_override) if working_dir_override else get_proc_cwd(pid)
        
        declared_task = None
        task_files: list[str] = []
        if cwd:
            declared_task, task_files = probe_task_files(cwd)

        agent_type = _detect_agent_type(env, task_files)
        declared_paths = _extract_heuristic_paths(declared_task or "")

        return AgentIntent(
            pid=pid,
            agent_type=agent_type,
            declared_paths=declared_paths,
            declared_task=declared_task,
            raw_env=env,
        )
    except Exception as exc:
        log.warning("extract_intent_defensive_fallback", pid=pid, error=str(exc))
        return AgentIntent(
            pid=pid,
            agent_type="unknown",
            declared_paths=[],
            declared_task=None,
            raw_env={},
        )
